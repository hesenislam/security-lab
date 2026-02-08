from flask import Flask, render_template, request
from scanner import scan

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    if request.method == "POST":
        target = request.form["target"]
        start_port = int(request.form["start_port"])
        end_port = int(request.form["end_port"])

        results = scan(target, start_port, end_port)

    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)
