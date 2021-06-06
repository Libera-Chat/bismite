# maskwatch-bot

IRC `nick!user@host real` watcher, akin to Atheme's OperServ `RWATCH`.

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
<jess> addmask /^jesstest!/ Please do not spam|!dnsbl
-bismite- added 1
<jess> listmask
-bismite-   1: /^jesstest!/ (0 hits) WARN [$spam|!dnsbl]
<jess> setmask 1 lethal
-bismite- /^jesstest!/ changed from WARN to LETHAL
<jess> getmask 1
-bismite-   1: /^jesstest!/ (0 hits) LETHAL [$spam|!dnsbl]
-bismite- changes:
-bismite-  2021-06-03T19:01:02 by jess: add
-bismite-  2021-06-03T19:01:10 by jess: type LETHAL
```

## commands

### ADDMASK
```
/msg bismite addmask /<regex>/ <reason>[|<oper reason>]
```

delimiters on `/<regex>/` can be any non-alphanumeric character, e.g. `,<regex>,`

### SETMASK
```
/msg bismite setmask <id> WARN|LETHAL|DLETHAL|EXCLUDE
```

### TOGGLEMASK
```
/msg bismite togglemask <id>
```

## mask types

### WARN

Prints a line to channel configured in `config.yaml` to tell you that someone
matched the pattern.

### LETHAL

Same as warn, but also k-lines the user.

### DLETHAL

Same as lethal, but the k-line is delayed a bit.

### EXCLUDE

Same as `WARN`, but is seen as more "important" than other mask types, and
will thus prevent people matching it from matching e.g. `LETHAL` masks.
