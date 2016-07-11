# this is example shows how you can add support for the custom inventory system
# in this example we will use /etc/hosts file and will select all machines
# whoes names match regexp provided via -I or --inventory options

class OSSH
    # you need to add get_inventory() method to the OSSH class
    def get_inventory()
        # method should return list of hashes
        # each hash should have :address entry with the ip of the target
        # it also can have optional :label entry which will be used in the output
        # if :label is not set ossh will try to resolve name of the target and use short name as a label
        # if name can't be resolved ip address will be used as a label
        inventory = []
        # @options[:inventory] contains regexp we use to select machines
        r = Regexp.new(@options[:inventory])
        IO.read('/etc/hosts')         # let's read conten of the /etc/hosts
            .split("\n")              # split it into individual lines
            .map{|x| x.sub(/#.*/, "") # remove comments
            .split(/\s+/)}            # turn each entry into array
            .select{|x| x.size > 1}   # filter out entries which have less than 2 elements (entry should have at least ip and name)
            .each do |h|
                ip = h.shift          # 1st element is an ip
                h.each do |name|
                    if name =~ r
                        # let's add another inventory entry and start processing next line in the /etc/hosts
                        inventory.push({:address => ip, :label => name.split(".")[0]})
                        break
                    end
                end
            end
        return inventory
    end
end
