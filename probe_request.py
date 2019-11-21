class ProbeRequest:
    
    def __init__(self, source_address, dest_address, other_address, rssi, time_recorded):
        self.source_address = source_address
        self.dest_address = dest_address
        self.other_address = other_address
        self.rssi = rssi
        self.time_recorded = time_recorded
    def __repr__(self):
        return '{source_address:' + str(self.source_address) + ', rssi:' + str(self.rssi) + '}'
