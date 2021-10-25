# COD-GO

`LIBRARY NO LONGER MAINTAINED`

`This library was built to support Warzone. Feel free to do a PR!`

## Installation
```
go get -u github.com/Fyb3roptik/cod-go
```

## Examples

### Creating A Session
```go
session := cod.Login("someuser@domain.com", "password")
```

### Logged In User Identities
```go
identites := session.GetIdentites("mw")
```

### Get Player Recent Matches
```go
stats := session.GetPlayerStats("uno", "SomeUser#12345678")
stats := session.GetPlayerStats("battle", "SomeUser#1234")
stats := session.GetPlayerStats("xbl", "SomeGamertag")
stats := session.GetPlayerStats("psn", "PsnOnlineId")
```
