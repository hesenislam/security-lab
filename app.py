from flask import Flask, render_template
from python_scripts.scanner import scan_results

app = Flask(__name__)

@app.route("/")
def index():
    results = scan_results()
    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)
