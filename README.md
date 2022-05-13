# bismite

IRC `nick!user@host real` watcher, akin to Atheme's OperServ `RWATCH`.

## setup

```
$ cp config.example.yaml config.yaml
$ vim config.yaml
$ sqlite3 ~/.masks.db < make-database.sql
```

## running

```
$ python3 -m bismite config.yaml
```

## quick usage examples

```
<jess> addreason spam Spam is not welcome on Libera Chat. Email $email with questions.
-bismite- added $spam
<jess> addreason email bans@libera.chat
-bismite- added $email
<jess> listreason
-bismite- $spam: Spam is not welcome on Libera Chat. Email $email with questions.
-bismite- $email: bans@libera.chat
<jess> testmask /^jesstest!/
-bismite- mask /^jesstest!/ matches...
-bismite-  010#jesstest!~j@sandcat.libera.chat j
-bismite- ... out of 7
<jess> addmask /^jesstest!/ $spam|!dnsbl
-bismite- added 1 (hits 1 out of last 8 users)
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

### TESTMASK
```
/msg bismite testmask /<regex>/

### ADDMASK
```
/msg bismite addmask /<regex>/ <reason>[|<oper reason>]
/msg bismite addmask %<glob>% <reason>[|<oper reason>]
/msg bismite addmask "<substring>" <reason>[|<oper reason>]
```

delimiters on `/<regex>/` can be any non-alphanumeric character, e.g.
`,<regex>,`

### SETMASK
```
/msg bismite setmask <id> WARN|LETHAL|DLETHAL|EXCLUDE
```

### TOGGLEMASK
```
/msg bismite togglemask <id>
```

### ADDREASON
```
/msg bismite addreason <alias> <text>
```
adds a reason template that can be used in mask reasons (see above example)

### DELREASON
```
/msg bismite delreason <alias>
```

### LISTREASON
```
/msg bismite listreason
```

## mask types

### WARN

Prints a line to channel configured in `config.yaml` to tell you that someone
matched the pattern.

### KILL

Same as `WARN`, but also issues a `/kill` for the user.

### LETHAL

Same as `WARN`, but also k-lines the user.

### DLETHAL

Same as `LETHAL`, but the k-line is delayed a bit.

### EXCLUDE

Same as `WARN`, but is seen as more "important" than other mask types, and
will thus prevent people matching it from matching e.g. `LETHAL` masks.

## mask flags
You can specify different flags to limit when a mask will be matched. For example to add mask flag `i`, use:

```
addmask /^beep!/i $spam|!dnsbl
```

The mask flags are as follows:
* `i` - case insensitive match
* `a` - only match users *with* an account
* `A` - only match users *without* an account
* `N` - also match on nick changes instead of just on connections
* `z` - only match users who *are* using TLS
* `Z` - only match users who *are not* using TLS
