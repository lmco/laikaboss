#!/usr/bin/env bash

set -euo pipefail

BASEDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="${BASEDIR}/.cache"

SWAGGER_CODEGEN_CLI_SOURCE_JAR="${SWAGGER_CODEGEN_CLI_SOURCE_JAR:-https://repo1.maven.org/maven2/io/swagger/swagger-codegen-cli/2.4.27/swagger-codegen-cli-2.4.27.jar}"
SWAGGER_CODEGEN_CLI_LOCAL_JAR="${SWAGGER_CODEGEN_CLI_LOCAL_JAR:-${CACHE_DIR}/swagger-codegen-cli.jar}"
SWAGGER_API_FILE="${SWAGGER_API_FILE:-${BASEDIR}/api/swagger.json}"
OUT_NODEJS="${OUT_NODEJS:-${BASEDIR}/apiServer}"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v java >/dev/null 2>&1; then
	echo "java is required to generate the Node.js API server" >&2
	exit 1
fi

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
	if command -v python >/dev/null 2>&1; then
		PYTHON_BIN="python"
	else
		echo "python3 or python is required to overlay the Node.js API implementation" >&2
		exit 1
	fi
fi

if ! command -v npm >/dev/null 2>&1; then
	echo "npm is required to install and run the generated Node.js API server" >&2
	exit 1
fi

mkdir -p "${CACHE_DIR}"

if [ ! -f "${SWAGGER_CODEGEN_CLI_LOCAL_JAR}" ]; then
	echo "Downloading Swagger Codegen CLI..."
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "${SWAGGER_CODEGEN_CLI_SOURCE_JAR}" -o "${SWAGGER_CODEGEN_CLI_LOCAL_JAR}"
	elif command -v wget >/dev/null 2>&1; then
		wget "${SWAGGER_CODEGEN_CLI_SOURCE_JAR}" -O "${SWAGGER_CODEGEN_CLI_LOCAL_JAR}"
	else
		echo "curl or wget is required to download Swagger Codegen CLI" >&2
		exit 1
	fi
fi

echo "Generating Node.js API server from ${SWAGGER_API_FILE}..."
rm -rf "${OUT_NODEJS}"
mkdir -p "${OUT_NODEJS}"

java -jar "${SWAGGER_CODEGEN_CLI_LOCAL_JAR}" generate \
	-i "${SWAGGER_API_FILE}" \
	-l nodejs-server \
	-o "${OUT_NODEJS}"

overlay_service() {
	local service_name="$1"
	local input_dir="${BASEDIR}/api/server/nodejs/functionScripts/${service_name}"
	local function_map_file="${input_dir}/functionMap.json"

	echo "Overlaying ${service_name} implementation..."

	"${PYTHON_BIN}" "${BASEDIR}/api/server/nodejs/overlayServerImplementation.py" \
		-i "${input_dir}" \
		-m "${function_map_file}" \
		-o "${OUT_NODEJS}/service" \
		-f "${service_name}.js"
}

overlay_service "ArtifactsService"
overlay_service "BlockchainService"
overlay_service "MetadataService"
overlay_service "RelationshipsService"
overlay_service "SystemTestService"

echo "Adding custom API extension methods..."
cat "${BASEDIR}/api/server/nodejs/writerFunctions.js" >> "${OUT_NODEJS}/utils/writer.js"
cat "${BASEDIR}/api/server/nodejs/customArtifactControllerFunctions.js" >> "${OUT_NODEJS}/controllers/Artifacts.js"
cp "${BASEDIR}/tools/digraphReducer.py" "${OUT_NODEJS}/utils/"

echo "Node.js API server generated at ${OUT_NODEJS}"
