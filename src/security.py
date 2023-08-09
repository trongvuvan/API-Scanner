from zapv2 import ZAPv2
import flask
import time
apiKey = 'tp4c52en8ll0p89im4eojakbr8'
zap = ZAPv2(apikey=apiKey, proxies={'http': 'https://127.0.0.1:8080/', 'https': 'https://127.0.0.1:8080/'})
def zapspider(url):
    target = url
    # Change to match the API key set in ZAP, or use None if the API key is disabled

    # By default ZAP API client will connect to port 8080
    # zap = ZAPv2(apikey=apiKey)
    # Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
    print('Spidering target {}'.format(target))
    # The scan returns a scan id to support concurrent scanning
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(scanID)))
        time.sleep(1)

    print('Spider has completed!')
    # Prints the URLs the spider has crawled
    return zap.spider.results(scanID)
def zapactivescan(target):
    # TODO : explore the app (Spider, etc) before using the Active Scan API, Refer the explore section
    print('Active Scanning target {}'.format(target))
    scanID = zap.ascan.scan(target)
#   print('Active Scanning target {}'.format(target))
    while int(zap.ascan.status(scanID)) < 100:
        # Loop until the scanner has finished
        print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
        time.sleep(1)

    print('Active Scan completed')
    # Print vulnerabilities found by the scanning
    print('Hosts: {}'.format(', '.join(zap.core.hosts)))
    print('Alerts: ')
    return zap.core.alerts(baseurl=target)

