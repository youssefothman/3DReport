import ssl, socket

# domains = [
# "cnn.com",
# "pichincha.com",
#
# ]

def get_issuer(hostname):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        try:
            s.settimeout(2)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return (cert['issuer'][1][0][1])
        except:
            return "N/A"
#
#
# for d in domains:
#     print(f"{d}\t{get_issuer(d)}")
#
