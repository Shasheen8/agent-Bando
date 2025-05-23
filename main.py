from flask import Flask, request, render_template
from agent import AgentBando
from utils.logger import log_info, log_error
import markdown
import traceback

app = Flask(__name__)
agent = AgentBando()

# Default test HTML
TEST_HTML = """
<h2>Test Summary</h2>
<ul>
    <li><strong>Test Item</strong>: This is a test.</li>
    <li>Nested
        <ul>
            <li>Nested item</li>
        </ul>
    </li>
</ul>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    summary_html = ""
    raw_summary = ""
    test_html = TEST_HTML
    error = None

    if request.method == "POST":
        query = request.form.get("query")
        if query:
            log_info(f"Received query: {query}")
            response = agent.process_query(query)
            if "error" in response:
                error = response["error"]
            else:
                results = response["results"]
                raw_summary = response["summary"]
                log_info(f"Raw Markdown summary: {raw_summary}")
                try:
                    # Test Markdown library
                    simple_md = "# Simple Test\n- Item 1\n- Item 2"
                    simple_html = markdown.markdown(
                        simple_md,
                        extensions=['extra', 'fenced_code', 'tables', 'nl2br', 'sane_lists'],
                        output_format='html5'
                    )
                    log_info(f"Simple Markdown: {simple_md}")
                    log_info(f"Simple HTML: {simple_html}")
                    # Render summary
                    summary_html = markdown.markdown(
                        raw_summary,
                        extensions=['extra', 'fenced_code', 'tables', 'nl2br', 'sane_lists'],
                        output_format='html5'
                    )
                    log_info(f"Rendered HTML summary: {summary_html}")
                except Exception as e:
                    log_error(f"Markdown rendering failed: {str(e)}\n{traceback.format_exc()}")
                    error = "Failed to render Markdown. Using raw text."
                    summary_html = f"<pre style='background-color: #f8f9fa; padding: 10px; border-radius: 4px;'>{raw_summary}</pre>"
        else:
            error = "Query cannot be empty"

    return render_template(
        "index.html",
        results=results,
        summary_html=summary_html,
        raw_summary=raw_summary,
        test_html=test_html,
        error=error
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)