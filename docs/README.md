# SentinelAI documentation

Start with [project status and roadmap](ROADMAP.md), then read the
[architecture](ARCHITECTURE.md) for the component you are changing.
[AGENTS.md](../AGENTS.md) owns security and human approval requirements.
Use the [glossary](../GLOSSARY.md) for domain terms and [ADRs](adr/) for decisions.

## Run and understand the application

| Guide | Use it for |
| --- | --- |
| [Local installation and analyst workflow](../README.md#local-installation) | Run the Level 1 dashboard and API |
| [Isolated Ubuntu development](UBUNTU_DEVELOPMENT.md) | Start the development VM and run PostgreSQL, Zeek, and the backend |
| [Architecture](ARCHITECTURE.md) | Components, request flows, and persistence |
| [FastAPI and request contracts](BACKEND_SETUP.md) | API startup, OpenAPI, and prediction examples |
| [PostgreSQL and migrations](DATABASE_SETUP.md) | Local connection settings, schema migrations, and integration tests |
| [Dashboard](DASHBOARD_SETUP.md) | CSV and JSON analysis, alerts, incidents, and notes |
| [Model packaging](MODEL_PACKAGING.md) | Build or load the trusted Level 1 artifact |
| [Testing and access boundaries](RELIABILITY_TESTING.md) | Reproduce the local workflow and understand its security assumptions |
| [G37 offline development closeout](G37_OFFLINE_PROVISIONING.md) | Review the demonstrated guest results, retained recovery media, and setup retrospective |
| [Coding standards](CODING_STANDARDS.md) | Run the pinned development checks and plan stack changes |

## Research and project material

| Guide | Use it for |
| --- | --- |
| [Level 1 official evaluation](FINAL_MODEL_EVALUATION.md) | Frozen model fingerprints, held-out metrics, and benchmark limits |
| [Controlled capture lab](LAB_GUIDE.md) | Authorized research procedures and historical G26–G36 evidence |
| [Research archive](research/README.md) | Dataset provenance, development experiments, negative findings, and capture evidence |
| [Datasets and citations](DATASETS_AND_CITATIONS.md) | Release identities, research roles, publisher references, and usage rights |
| [Status and roadmap](ROADMAP.md) | Implemented capabilities and next research work |
| [Engineering review](G27_5_ENGINEERING_REVIEW.md) | Priorities, safe refactors, verification, and remaining debt |
| [Level 1 technical report](TECHNICAL_REPORT.md) | Academic methodology and system implementation |
| [Project explanation](../PROJECT_EXPLANATION.md) | Beginner-friendly walkthrough |
| [Presentation and demo](PRESENTATION_AND_DEMO.md) | Suggested graduation presentation and local demonstration |
