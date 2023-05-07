# bismite

IRC mask watcher, akin to Atheme's OperServ `RWATCH`.

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

## quick usage examples=
```
<jess> addreason spam Spam is not welcome on Libera Chat. Email $email with questions.
-bismite- added $spam
<jess> addreason email bans@libera.chat
-bismite- added $email
<jess> listreason
-bismite- $spam: Spam is not welcome on Libera Chat. Email $email with questions.
-bismite- $email: bans@libera.chat
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

### ADDMASK
```
/msg bismite addmask /<regex>/[<flags>] <reason>[|<oper reason>]
/msg bismite addmask %<glob>%[<flags>] <reason>[|<oper reason>]
/msg bismite addmask "<string>"[<flags>] <reason>[|<oper reason>]
```

Adds a "mask", a pattern that will be tested against new connections' masks
(formatted as `nick!user@host realname`).
By default, all new masks are `WARN` masks.

The delimiters on `/<regex>/` can be any non-alphanumeric character, e.g. `,<regex>,`.
bismite's regex syntax can be found [here](https://docs.python.org/3/library/re.html#regular-expression-syntax).

`flags` is an optional sequence of [flag characters](#mask-flags)
that further controls how the provided pattern matches.

`reason` is the publicly-visible reason for any actions (e.g. K-lines) taken by bismite.
`oper-reason` is private.

This command will return an integer ID for the newly-added mask,
which should be used in any commands with an `<id>` parameter.

### SETMASK
```
/msg bismite setmask <id> <mask-type>
```

Changes the action taken when a mask matches. See [mask types](#mask-types).

Lists all masks and their IDs.

### TOGGLEMASK
```
/msg bismite togglemask <id>
```

Enables or disables a mask.

### LISTMASK
```
/msg bismite listmask
```

Lists all masks and their IDs.

### GETMASK
```
/msg bismite getmask <id>
```

Gets detailed information about a mask, including a log of changes to it and who made them.

### ADDREASON
```
/msg bismite addreason <alias> <text>
```

Adds a reason template.
In mask reasons, `$alias` will be replaced with `text`.

### DELREASON
```
/msg bismite delreason <alias>
```

Deletes a reason template.

### LISTREASON
```
/msg bismite listreason
```

Lists all reason templates.

## mask types

Every mask type is made up of one action and zero or more modifiers separated by `|`,
e.g. `LETHAL|DELAY|QUICK`.

By default, every action except `EXCLUDE` is logged to two channels,
both of which are configured in `config.yaml` as `channel` and `verbose`.

The actions are as follows:
* `WARN`: Does nothing except send a warning message to the channel.
* `RESV`: Applies a temporary `RESV` with the user's nick.
* `KILL`: Disconnects the user using a `KILL` command.
* `LETHAL`: Bans the user using the `bancmd` in `config.yaml`.
* `EXCLUDE`: Does nothing. Takes priority over other mask types,
preventing them from matching.

The modifiers are as follows:
* `DELAY`: Waits for a small random number of seconds before performing an action.
* `QUICK`: When combined with `DELAY`, waits for a shorter-on-average and consistent duration before performing an action.
* `QUIET`: Only logs to the verbose channel.
* `SILENT`: Prevents logging to either channel.

## mask flags

You can specify different flags to limit when a mask will be matched. For example,
to perform case-insensitive matching on connections without accounts, use:

```
addmask /^beep!/iA $spam
```

The mask flags are as follows:
* `i` - case insensitive match
* `a` - only match users *with* an account
* `A` - only match users *without* an account
* `N` - also match on nick changes instead of just on connections
* `z` - only match users who *are* using TLS
* `Z` - only match users who *are not* using TLS
