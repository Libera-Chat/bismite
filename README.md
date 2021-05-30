# maskwatch-bot

## setup

```
$ cp config.example.yaml config.yaml
$ vim config.yaml
$ sqlite3 ~/.masks.db < make-database.sql
```

## running

```
$ python3 -m maskwatch-bot config.yaml
```

## quick usage examples

```
17:43 <jess> addmask /^jesstest!/ Spam is unwelcome on Libera.Chat
17:43 -jmasks(~jmasks@libera/staff/jess)- added 1
17:43 <jess> listmask
17:43 -jmasks(~jmasks@libera/staff/jess)-   1: /^jesstest!/ (0 hits) WARN [Spam is unwelcome on Libera.Chat]
17:43 <jess> togglemask 1
17:43 -jmasks(~jmasks@libera/staff/jess)- mask 1 disabled
17:43 <jess> listmask
17:43 -jmasks(~jmasks@libera/staff/jess)- no masks
17:43 <jess> togglemask 1
17:43 -jmasks(~jmasks@libera/staff/jess)- mask 1 enabled
17:43 <jess> listmask
17:43 -jmasks(~jmasks@libera/staff/jess)-   1: /^jesstest!/ (0 hits) WARN [Spam is unwelcome on Libera.Chat]
17:43 <jess> setmask 1 lethal
17:43 -jmasks(~jmasks@libera/staff/jess)- /^jesstest!/ changed from WARN to LETHAL
17:43 <jess> listmask
17:43 -jmasks(~jmasks@libera/staff/jess)-   1: /^jesstest!/ (0 hits) LETHAL [Spam is unwelcome on Libera.Chat]
```
