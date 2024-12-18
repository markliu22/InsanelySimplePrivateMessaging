## Insanely simple and private peer-to-peer messaging app.

No Persistent Data: your chats and accounts are deleted as soon as you close the app.

No Servers: peer-to-peer communication - no data is processed or stored with third parties.

Simple Setup: generate an identifier, tell your buddy. That's how he/she will recognize you and you can start chatting.

Secure: end-to-end encryption assures your messages stay private.

## How To Run

Git clone this repo and run:
```
go mod tidy
```

```
go build -o messenger
```
In terminal 1:
```
./messenger 1
/advertise
note down the output of "Your identifier:" here
```
In terminal 2:
```
./messenger 2
/discover <identifier from terminal 1>
```



TODO

## How It Works
