import dpkt
import socket
import pygeoip

gi = pygeoip.GeoIP('GeoLiteCity.dat')

def main():
    f = open('wire.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
    '<Style id="transBluePoly">'\
        '<LineStyle>'\
            '<width>1.5</width>'\
            '<color>501400E6</color>'\
        '</LineStyle>'\
    '</Style>'
    kmlfooter = '</Document>\n</kml>\n'
    kmldoc = kmlheader + plotIPs(pcap) + kmlfooter
    print(kmldoc)
    saveToKML(kmldoc)  # Save the KML content to a file
    
def plotIPs(pcap):
    kmlPts = ''
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = ip.src
            dst = ip.dst
            print('Detected TCP connection from %s to %s' % (socket.inet_ntoa(src), socket.inet_ntoa(dst)))
            KML = retKML(socket.inet_ntoa(dst), '103.13.42.183')
            kmlPts = kmlPts + KML
        except:
            pass
    return kmlPts  
    
def retKML(dstip, srcip):
    dst = gi.record_by_name(dstip)
    if dst is None:
        return ''
    src = gi.record_by_name(srcip) 
    if src is None:
        return ''
    try:
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']
        print('Generated coordinates for %s -> %s: (%f, %f) -> (%f, %f)' % (srcip, dstip, srclatitude, srclongitude, dstlatitude, dstlongitude))
        kml = (
           '<Placemark>\n'
            '<name>%s</name>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'  # Fix 2: Add styleUrl attribute
            '<LineString>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<altitudeMode>relativeToGround</altitudeMode>\n'
            '<coordinates>%f,%f,0 %f,%f,0</coordinates>\n'  # Fix 3: Use the correct format specifier for coordinates
            '</LineString>\n'
            '</Placemark>\n'
        )%(dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
        return kml
    except:
        return ''

def saveToKML(kmldoc):
    with open('output.kml', 'w') as f:
        f.write(kmldoc)
        print("KML file saved as 'output.kml'")

if __name__ == '__main__':
    main()
