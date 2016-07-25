# -*- encoding: utf-8 -*-

Gem::Specification.new do |g|
    g.authors       = ["Kirill Timofeev"]
    g.email         = ["kt97679@gmail.com"]
    g.description   = %q{Tool to run commands via ssh on multiple hostshosts}
    g.summary       = %q{You can specify what hosts you are interested in and run commands via ssh on those hosts. Inspired by knife from chef.}
    g.name          = "ossh"
    g.version       = "1.0.0"
    g.files         = %w(bin/ossh lib/ossh.rb)
    g.bindir        = "bin"
    g.executables   << "ossh"
    g.require_paths << "lib"
    %w(highline em-ssh bracecomp).each do |x|
        g.add_dependency(x)
    end
end
