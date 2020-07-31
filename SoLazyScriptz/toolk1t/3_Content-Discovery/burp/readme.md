# Burp Setup and Addons

## Useful addons for burp professional (Authorize and Auto Repeater)
https://www.youtube.com/watch?v=3K1-a7dnA60

## configuration for turbo intruder
```
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=True
                           )
    engine.start()

    for i in range(3, 8):
        engine.queue(target.req, randstr(i), learn=1)
        engine.queue(target.req, target.baseInput, learn=2)

    for word in open('C:\\path\\to\\wordlist.txt'):
        engine.queue(target.req, word.rstrip())


def handleResponse(req, interesting):
    if interesting:
        table.add(req)
```

