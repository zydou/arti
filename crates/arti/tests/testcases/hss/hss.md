# `arti hss`

## The `onion-name` subcommand

Print the `.onion` address of a hidden service:

```console
$ arti -c hss.toml hss --nickname acutus-cepa onion-name
mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion

```

If the service is not configured, or if it does not yet have an identity key
(i.e. if it has never been launched before), `arti hss onion-name` displays an
error and exits with a non-zero exit code:

```
$ arti -c hss.toml hss --nickname flamingo onion-name
? 127
[..]/arti: error: Service flamingo is not configured

$ arti -c hss.toml hss --nickname allium-cepa onion-name
? 127
[..]/arti: error: Service allium-cepa does not exist, or does not have an K_hsid yet

```

With `--generate=if-needed`, `onion-name` will generate the key if it doesn't
already exist:


```ignore
$ arti -c hss.toml hss --nickname allium-cepa onion-name --generate=if-needed
[..].onion
```
