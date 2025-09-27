Flask Notes – Beginner to Intermediate
1. What is Flask?

Flask is a Python micro web framework for creating web applications.

Lightweight, simple, and flexible — ideal for learning and small projects.

2. Installing Flask
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install flask

3. Basic Flask App Structure
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello, Flask is running!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

Key Points:

Flask(__name__) → creates the app instance.

@app.route("/") → maps a URL path to a Python function.

app.run(host="0.0.0.0", port=5000) → starts the server accessible from any network interface.

4. Routes

Routes define URLs that your app responds to.

@app.route("/about")
def about():
    return "About page"


Multiple routes can be added for multiple pages:

/ → Home

/about → About page

/contact → Contact page

5. Handling POST Data

Use request to get data from a POST request:

from flask import Flask, request

@app.route("/update", methods=["POST"])
def update_message():
    global latest_message
    latest_message = request.form.get("message", "No message sent")
    return "Message updated!"


request.form.get("message", default) → fetches a value from POST data safely.

Global variable is needed to update a variable outside the function.

6. Default Values and Global Variables

Initial assignment:

latest_message = "No message yet."


Ensures the variable exists before any updates, so the homepage can display it.

POST default:

request.form.get("message", "No message sent")


Used if a client sends no data in a POST request.

7. render_template vs render_template_string

render_template_string → render HTML from a string (good for small projects).

render_template → render HTML from a file in templates/ folder (better for bigger projects).

Example:

from flask import render_template_string
return render_template_string("<h1>{{ message }}</h1>", message=latest_message)

8. HTTP 405 Error

405 Method Not Allowed → occurs when using a method (GET/POST) not allowed on a route.

Fix: specify allowed methods in route:

@app.route("/update", methods=["POST"])

9. Minimal Flask App without Extra Imports

If you only return plain text, you can just import Flask:

from flask import Flask


You don’t need request or render_template unless handling POST data or HTML.

10. Sending Data to Flask from Another Script

Example Python script (sender.py) sending data:

import requests

requests.post("http://127.0.0.1:5000/update", data={"message": "Hello!"})


Works with POST route on Flask app to update variables.

11. Running Multiple Scripts on Ubuntu

Separate terminals:

python3 app.py
python3 sender.py


Background jobs:

python3 app.py &
python3 sender.py &


tmux (recommended):

Install: sudo apt install tmux -y

Split panes: Ctrl+B then " (horizontal) or % (vertical)

Move panes: Ctrl+B then arrow keys

Detach: Ctrl+B then D

Reattach: tmux attach

12. Flask + Global Variable Flow

Flask defines latest_message → initial value.

/update route updates it via POST.

/ route reads it and displays on the browser.

POST default ensures no empty value if nothing is sent.

13. Summary of Best Practices

Use app as variable name for clarity, but any name works (you, myapp).

Separate display routes and update routes for clean design.

Use render_template for HTML pages in bigger projects.

Specify HTTP methods in routes to avoid 405 errors.

Use tmux or screen to manage multiple scripts on a server.

Initial values are important for global variables to avoid errors before updates.

