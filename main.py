from flask import Flask, render_template, request
from agent import AgentBando

app = Flask(__name__)
agent = AgentBando()

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    summary = ""
    error = ""

    if request.method == "POST":
        query = request.form.get("query")
        if query:
            response = agent.process_query(query)
            if "error" in response:
                error = response["error"]
            else:
                results = response["results"]
                summary = response["summary"]

    return render_template("index.html", results=results, summary=summary, error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)