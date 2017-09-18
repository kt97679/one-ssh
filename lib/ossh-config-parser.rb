require 'yaml'
require 'securerandom'

OSSHConfigParserException = Class.new(Exception)

class OSSHConfigParser
    def initialize()
        @parsed_files = []
    end

    def parse(config_file)
        config_file = File.realpath(config_file)
        if @parsed_files.include?(config_file)
            return ""
        end
        @parsed_files.push(config_file)
        config_dir = File.dirname(config_file)
        command_list = []
        config = YAML.load_file(config_file)
        config.each do |entry|
            entry.each_pair do |method_name, method_data|
                method_sym = method_name.to_sym
                if OSSHConfigParser.method_defined?(method_sym)
                    command_list.push(public_send(method_sym, method_data, config_dir))
                else
                    raise OSSHConfigParserException.new("Unknown action #{k}")
                end
            end
        end
        return command_list.flatten()
    end

    def shell(data, config_dir)
        if data["inline"] && data["from"]
            raise OSSHConfigParserException.new("Shell action should have either 'script' or 'file' attribute, not both")
        end
        if data["inline"]
            return data["inline"]
        end
        if data["from"]
            return IO.read(File.join(config_dir, data["from"]))
        end
        raise OSSHConfigParserException.new("Shell action should have either 'inline' or 'from'")
    end

    def file(data, config_dir)
        if data["inline"] && data["from"]
            raise OSSHConfigParserException.new("File action should have either 'inline' or 'from' attribute, not both")
        end
        if data['to'].nil?
            raise OSSHConfigParserException.new("File action should have 'to' attribute")
        end
        delimiter = SecureRandom.hex
        if data["inline"]
            return "head -c -1 > #{data['to']} <<'#{delimiter}'\n" + data["inline"] + "\n#{delimiter}"
        end
        if data["from"]
            return "head -c -1 > #{data['to']} <<'#{delimiter}'\n" + IO.read(File.join(config_dir, data["from"])) + "\n#{delimiter}"
        end
        raise OSSHConfigParserException.new("File action should have either 'inline' or 'from'")
    end

    def include(data, config_dir)
        command_list = []
        data.each do |config_file|
            command_list.push(parse(File.join(config_dir, config_file)))
        end
        return command_list
    end
end
