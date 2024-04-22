Machine problem 3
=================

This sample application requires Python, sqlite3, and Flask.

Initial setup
-------------

Setup a Python virtual environment to install Flask in a contained project.

```
$ python -m venv virtualenv
```

This should create a virtual environment in a folder named `virtualenv`.
Activate this environment with:

```
$ source ./virtualenv/bin/activate
(virtualenv) $
```

Typically, a change in the prompt like seen above indicates the virtual environment activation was successful.

(On Windows, consult the `Activate.ps1` script in `./virtualenv/bin/`.)

Install the rest of the requirements with:

```
(virtualenv) $ pip install -r requirements.txt
```

Running 
-------

Run the web application with:

```
$ flask run
```

This should run the application on port `5000`.

Open a web browser to `http://localhost:5000` and the application should be there.

Database
--------

The database contains three tables: `users`, `sessions`, and `posts`.

The `users` table contains `username`s and `password`s.

`sessions` contains a mapping between `users` and a generated session token.

`posts` contains posts that users see on their homepage.

The database should have a single user preloaded: `alice` with password `12345678`.
