text = File.read("./dummy_users.tsv")

File.open("../go/hash.go", "w") do |file|
  file << <<-EOS
package main

import (
	"errors"
)

var (
	userByLogin = map[string]User{
  EOS

  limit = -1
  text.each_line.with_index do |line, index|
    id, login, pass, salt, password_hash = line.strip.split("\t")
    #file << "     '#{login}' => { 'id' => #{id}, 'salt' => '#{salt}', 'password_hash' => '#{password_hash}' },\n"
    file << <<-EOS
		"#{login}": User{ ID: #{id}, Login: "#{login}", PasswordHash: "#{password_hash}", Salt: "#{salt}" },
    EOS

    break if index == limit
  end

  file << <<-EOS
	}
)

func findUserByLogin(loginName string) (*User, error) {
	if user, ok := userByLogin[loginName]; ok {
		return &user, nil
	}	else {
		return nil, errors.New("User not found")
	}
}
  EOS
end
