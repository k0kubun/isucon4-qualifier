source = ""

text = File.read("./dummy_users.tsv")
text.each_line do |line|
  id, login, pass, salt, password_hash = line.strip.split("\t")
  source += "#{id} => { id: #{id}, salt: '#{salt}', password_hash: '#{password_hash}' }"
  break
end

File.write("src.rb", source)
