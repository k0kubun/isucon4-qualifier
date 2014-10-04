require 'sinatra/base'
require 'digest/sha2'
require 'mysql2-cs-bind'
require 'rack-flash'
require 'json'
require "rack-lineprof"
require "redis"
require_relative "./users"

module Isucon4
  class App < Sinatra::Base
    use Rack::Session::Cookie, secret: ENV['ISU4_SESSION_SECRET'] || 'shirokane'
    use Rack::Flash
    use Rack::Lineprof, profile: "app.rb" if ENV["RACK_ENV"] != "production"
    set :public_folder, File.expand_path('../../public', __FILE__)

    helpers do
      def config
        @config ||= {
          user_lock_threshold: (ENV['ISU4_USER_LOCK_THRESHOLD'] || 3).to_i,
          ip_ban_threshold: (ENV['ISU4_IP_BAN_THRESHOLD'] || 10).to_i,
        }
      end

      def db
        Thread.current[:isu4_db] ||= Mysql2::Client.new(
          socket: ENV['ISU4_DB_SOCKET'] || '/tmp/mysql.sock',
          username: ENV['ISU4_DB_USER'] || 'root',
          password: ENV['ISU4_DB_PASSWORD'],
          database: ENV['ISU4_DB_NAME'] || 'isu4_qualifier',
          reconnect: true,
        )
      end

      def redis
        @redis ||= Redis.new(path: "/tmp/redis.sock")
      end

      def calculate_password_hash(password, salt)
        Digest::SHA256.hexdigest "#{password}:#{salt}"
      end

      def login_log(succeeded, login, user_id = nil)
        redis_login_log(succeeded, login, user_id)
      end

      def redis_login_log(succeeded, login, user_id, created_at = Time.now.strftime("%Y-%m-%d %H:%M:%S"), ip = request.ip)
        if succeeded
          redis.set("login_failure_ip_#{ip}", 0)
          redis.set("login_failure_user_id_#{user_id}", 0)

          current_login = {
            created_at: created_at,
            ip: ip,
            login: login,
          }
          last_login = redis.get("current_login_#{user_id}")

          redis.set("current_login_#{user_id}", Marshal.dump(current_login))
          redis.set("last_login_#{user_id}", last_login) if last_login
        else
          failures = redis.incr("login_failure_ip_#{ip}")
          if config[:ip_ban_threshold] <= failures
            redis.sadd("banned_ips", ip)
          end

          failures = redis.incr("login_failure_user_id_#{user_id}")
          if config[:user_lock_threshold] <= failures
            redis.sadd("locked_users", login)
          end
        end
      end

      def user_locked?(user)
        return nil unless user
        config[:user_lock_threshold] <= redis.get("login_failure_user_id_#{user['id']}").to_i
      end

      def ip_banned?
        config[:ip_ban_threshold] <= redis.get("login_failure_ip_#{request.ip}").to_i
      end

      def attempt_login(login, password)
        # user = db.xquery('SELECT * FROM users WHERE login = ?', login).first # 0.8ms
        user = USER_BY_LOGIN[login]

        if ip_banned? # 0.5ms
          # This will be validated in /report
          login_log(false, login, user ? user['id'] : nil)
          return [nil, :banned]
        end

        if user_locked?(user) # 0.3ms
          # This will be validated in /report
          login_log(false, login, user['id'])
          return [nil, :locked]
        end

        if user && calculate_password_hash(password, user['salt']) == user['password_hash']
          login_log(true, login, user['id']) # 15.9ms
          [user, nil]
        elsif user
          # This affects ban judgement
          login_log(false, login, user['id'])
          [nil, :wrong_password]
        else
          # This affects ban judgement
          login_log(false, login)
          [nil, :wrong_login]
        end
      end

      def current_user
        return @current_user if @current_user
        return nil unless session[:user_id]

        @current_user = db.xquery('SELECT * FROM users WHERE id = ?', session[:user_id].to_i).first
        unless @current_user
          session[:user_id] = nil
          return nil
        end

        @current_user
      end

      # Shown in /mypage
      # This affects check result
      def last_login
        return nil unless current_user

        raw_current = redis.get("current_login_#{current_user['id']}")
        raw_last = redis.get("last_login_#{current_user['id']}")

        Marshal.load([raw_current, raw_last].compact.last)
      end

      def banned_ips
        redis.smembers("banned_ips")
      end

      def locked_users
        redis.smembers("locked_users")
      end
    end

    get '/' do
      erb :index, layout: :base
    end

    post '/login' do
      user, err = attempt_login(params[:login], params[:password]) # 17.5ms
      if user
        session[:user_id] = user['id'] # 0.3ms
        redirect '/mypage'
      else
        case err
        when :locked
          redirect '/?err=locked'
        when :banned
          redirect '/?err=banned'
        else
          redirect '/?err=wrong'
        end
      end
    end

    get '/mypage' do
      unless current_user
        redirect '/?err=invalid'
      end
      erb :mypage, layout: :base
    end

    # Validated necessary parameters
    #   banned_ips:   all banned user's `request.ip`
    #   locked_users: all locked user's `users.login`
    get '/report' do
      redis.save

      content_type :json
      {
        banned_ips: banned_ips,
        locked_users: locked_users,
      }.to_json
    end

    get '/init' do
      last_id = db.xquery("SELECT MAX(id) AS last_id FROM login_log").first["last_id"]
      (1..last_id).each_slice(10000) do |ids|
        login_logs = db.xquery("SELECT * FROM login_log WHERE id IN (#{ids.join(',')})").to_a
        login_logs.each do |login_log|
          redis_login_log(
            login_log['succeeded'] == 1,
            login_log['login'],
            login_log['user_id'],
            login_log['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
            login_log['ip'],
          )
        end
      end
    end
  end
end
