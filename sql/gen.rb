text = File.read("./dummy_users.tsv")

File.open("users.rb", "w") do |file|
  file << "USER_BY_LOGIN = {\n"

  text.each_line do |line|
    id, login, pass, salt, password_hash = line.strip.split("\t")
    file << "  :'#{login}' => { id: #{id}, salt: '#{salt}', password_hash: '#{password_hash}' },\n"
  end

  file << "}"
end
