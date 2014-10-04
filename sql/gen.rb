source = ""

text = File.read("./dummy_users.tsv")
text.each_line do |line|
  id, login, pass, salt, password_hash = line.strip.split("\t")
  source += ":'#{login}' => { id: #{id}, salt: '#{salt}', password_hash: '#{password_hash}' }"
  print "#{id}         \r"
end

File.write("src.rb", source)
