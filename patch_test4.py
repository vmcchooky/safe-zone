import re

test_path = "internal/api/handlers/api_test.go"
with open(test_path, "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace("api.DeploymentTier", "api.Config.DeploymentTier")
content = re.sub(r'httputil\.LogRequests\("core-api", (.*?), api\.Metrics\)', r'httputil.LogRequests("core-api", api.Metrics)(\1)', content)
content = content.replace("risk: ", "Risk: ")
content = content.replace("metrics: ", "Metrics: ")
content = content.replace("adminAPIKey: ", "Config: Config{AdminAPIKey: ")
content = content.replace("deploymentTier: ", "Config: Config{DeploymentTier: ")
# We'll just replace `Config: Config{...}` correctly... this is hard with regex.
# Actually I'll just change `api := &Handler{...}` to `api := New(...)`.

init1 = r'api := &Handler{Risk: risk.NewService\(.*?\), Config: Config\{DeploymentTier: "test", \}\}'
content = re.sub(init1, 'api := New(risk.NewService(risk.Options{}), observability.NewRegistry(), Config{DeploymentTier: "test"})', content)

# Remove the statusResponse block at the end
struct_regex = r'type statusResponse struct \{.*?\n\}\n'
content = re.sub(struct_regex, '', content, flags=re.DOTALL)

with open(test_path, "w", encoding="utf-8") as f:
    f.write(content)
