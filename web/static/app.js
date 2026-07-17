"use strict";

const API_URL = "/api/v1/csr/parse";
const MAX_CLIENT_FILE_SIZE = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15000;

const SUPPORTED_PEM_TYPES = new Set([
    "CERTIFICATE REQUEST",
    "NEW CERTIFICATE REQUEST",
]);

const elements = {
    input: document.getElementById("csr-input"),

    fileInput: document.getElementById("csr-file-input"),
    dropZone: document.getElementById("drop-zone"),
    selectedFileName: document.getElementById(
        "selected-file-name",
    ),

    parseButton: document.getElementById("parse-button"),
    clearButton: document.getElementById("clear-button"),
    copyJSONButton: document.getElementById(
        "copy-json-button",
    ),

    requestStatus: document.getElementById(
        "request-status",
    ),

    errorPanel: document.getElementById("error-panel"),
    errorMessage: document.getElementById(
        "error-message",
    ),

    resultRoot: document.getElementById("result-root"),

    warningsPanel: document.getElementById(
        "warnings-panel",
    ),

    warningsList: document.getElementById(
        "warnings-list",
    ),

    findingsPanel: document.getElementById(
    "findings-panel",
    ),

    findingsContent: document.getElementById(
        "findings-content",
    ),

    subjectSummary: document.getElementById(
        "subject-summary",
    ),

    sanContent: document.getElementById("san-content"),

    publicKeyContent: document.getElementById(
        "public-key-content",
    ),

    signatureContent: document.getElementById(
        "signature-content",
    ),

    rdnContent: document.getElementById("rdn-content"),

    extensionsContent: document.getElementById(
        "extensions-content",
    ),

    rawJSON: document.getElementById("raw-json"),
};

let lastResult = null;

function createElement(tagName, className, text) {
    const element = document.createElement(tagName);

    if (className) {
        element.className = className;
    }

    if (text !== undefined && text !== null) {
        element.textContent = String(text);
    }

    return element;
}

function clearElement(element) {
    element.replaceChildren();
}

function normalizeValue(value) {
    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {
        return "—";
    }

    if (typeof value === "boolean") {
        return value ? "Yes" : "No";
    }

    return String(value);
}

function appendField(container, label, value) {
    const labelElement = createElement(
        "div",
        "field-label",
        label,
    );

    const normalized = normalizeValue(value);

    const valueClass = normalized === "—"
        ? "field-value empty-value"
        : "field-value";

    const valueElement = createElement(
        "div",
        valueClass,
        normalized,
    );

    container.append(labelElement, valueElement);
}

function humanizeKey(key) {
    return key
        .replaceAll("_", " ")
        .replace(
            /\b\w/g,
            (letter) => letter.toUpperCase(),
        );
}

function formatPKCS10Version(version) {
    if (version === 0) {
        return "Version 1 (encoded value: 0)";
    }

    if (
        version === undefined ||
        version === null
    ) {
        return null;
    }

    return `Unknown version (encoded value: ${version})`;
}

function renderSubject(subject, result) {
    clearElement(elements.subjectSummary);

    appendField(
        elements.subjectSummary,
        "PEM type",
        result.pem_type,
    );

    appendField(
        elements.subjectSummary,
        "PKCS#10 version",
        formatPKCS10Version(result.version),
    );

    appendField(
        elements.subjectSummary,
        "Common Name",
        subject?.common_name,
    );

    appendField(
        elements.subjectSummary,
        "Full subject",
        subject?.string,
    );
}

function renderValueList(container, title, values) {
    const group = createElement("div", "san-group");

    group.append(
        createElement(
            "h3",
            "san-group-title",
            title,
        ),
    );

    if (!Array.isArray(values) || values.length === 0) {
        group.append(
            createElement(
                "div",
                "empty-value",
                "None",
            ),
        );

        container.append(group);

        return;
    }

    const list = createElement("ul", "value-list");

    for (const value of values) {
        list.append(
            createElement(
                "li",
                "value-list-item",
                value,
            ),
        );
    }

    group.append(list);
    container.append(group);
}

function renderSAN(san) {
    clearElement(elements.sanContent);

    renderValueList(
        elements.sanContent,
        "DNS names",
        san?.dns_names,
    );

    renderValueList(
        elements.sanContent,
        "IP addresses",
        san?.ip_addresses,
    );

    renderValueList(
        elements.sanContent,
        "Email addresses",
        san?.email_addresses,
    );

    renderValueList(
        elements.sanContent,
        "URIs",
        san?.uris,
    );
}

function appendObjectFields(container, title, object) {
    if (!object || typeof object !== "object") {
        return;
    }

    for (const [key, value] of Object.entries(object)) {
        if (
            value === undefined ||
            value === null ||
            typeof value === "object"
        ) {
            continue;
        }

        appendField(
            container,
            `${title} ${humanizeKey(key)}`,
            value,
        );
    }
}

function renderPublicKey(publicKey) {
    clearElement(elements.publicKeyContent);

    appendField(
        elements.publicKeyContent,
        "Algorithm",
        publicKey?.algorithm || publicKey?.display_name,
    );

    appendField(
        elements.publicKeyContent,
        "Algorithm OID",
        publicKey?.algorithm_oid,
    );

    appendField(
        elements.publicKeyContent,
        "Key size",
        publicKey?.bits
            ? `${publicKey.bits} bits`
            : null,
    );

    appendField(
        elements.publicKeyContent,
        "SHA-256 fingerprint",
        publicKey?.fingerprint_sha256,
    );

    appendObjectFields(
        elements.publicKeyContent,
        "RSA",
        publicKey?.rsa,
    );

    appendObjectFields(
        elements.publicKeyContent,
        "ECDSA",
        publicKey?.ecdsa,
    );

    appendObjectFields(
        elements.publicKeyContent,
        "Ed25519",
        publicKey?.ed25519,
    );

    appendObjectFields(
        elements.publicKeyContent,
        "DSA",
        publicKey?.dsa,
    );

    appendObjectFields(
        elements.publicKeyContent,
        "GOST",
        publicKey?.gost,
    );
}

function verificationPresentation(status) {
    switch (status) {
    case "valid":
        return {
            className: "badge badge-valid",
            title: "Valid",
            description:
                "The CSR self-signature is mathematically valid.",
        };

    case "invalid":
        return {
            className: "badge badge-invalid",
            title: "Invalid",
            description:
                "The CSR self-signature is mathematically invalid.",
        };

    case "not_verified":
        return {
            className: "badge badge-unsupported",
            title: "Not verified",
            description:
                "The CSR self-signature was not checked. " +
                "See the verification details and quality findings below.",
        };

    case "unsupported":
        return {
            className: "badge badge-unsupported",
            title: "Not supported",
            description:
                "Signature verification is not currently supported " +
                "for this algorithm. The CSR fields were parsed " +
                "without verifying the self-signature.",
        };

    default:
        return {
            className: "badge badge-unknown",
            title: "Unknown",
            description:
                "The CSR signature verification status is unknown.",
        };
    }
}

function renderSignature(signature) {
    clearElement(elements.signatureContent);

    const presentation = verificationPresentation(
        signature?.verification,
    );

    elements.signatureContent.append(
        createElement(
            "span",
            presentation.className,
            presentation.title,
        ),
    );

    elements.signatureContent.append(
        createElement(
            "p",
            "signature-description",
            presentation.description,
        ),
    );

    const fields = createElement(
        "div",
        "field-grid",
    );

    appendField(
        fields,
        "Signature algorithm",
        signature?.algorithm || signature?.display_name,
    );

    appendField(
        fields,
        "Signature OID",
        signature?.algorithm_oid,
    );

    appendField(
        fields,
        "Hash algorithm",
        signature?.hash_algorithm,
    );

    appendField(
        fields,
        "Key algorithm",
        signature?.key_algorithm,
    );

    if (signature?.verification_error) {
        appendField(
            fields,
            "Verification details",
            signature.verification_error,
        );
    }

    elements.signatureContent.append(fields);
}

function renderRDNs(subject) {
    clearElement(elements.rdnContent);

    const attributes = [];

    for (const rdn of subject?.rdns || []) {
        for (const attribute of rdn?.attributes || []) {
            attributes.push(attribute);
        }
    }

    if (attributes.length === 0) {
        elements.rdnContent.append(
            createElement(
                "div",
                "empty-value",
                "No distinguished name attributes",
            ),
        );

        return;
    }

    const table = createElement("table", "rdn-table");
    const head = document.createElement("thead");
    const headRow = document.createElement("tr");

    for (const title of ["Name", "OID", "Value"]) {
        headRow.append(
            createElement("th", "", title),
        );
    }

    head.append(headRow);

    const body = document.createElement("tbody");

    for (const attribute of attributes) {
        const row = document.createElement("tr");

        row.append(
            createElement(
                "td",
                "",
                attribute.name || "Unknown",
            ),
        );

        row.append(
            createElement(
                "td",
                "",
                attribute.oid,
            ),
        );

        row.append(
            createElement(
                "td",
                "",
                attribute.value,
            ),
        );

        body.append(row);
    }

    table.append(head, body);
    elements.rdnContent.append(table);
}

function renderExtensions(extensions) {
    clearElement(elements.extensionsContent);

    if (
        !Array.isArray(extensions) ||
        extensions.length === 0
    ) {
        elements.extensionsContent.append(
            createElement(
                "div",
                "empty-value",
                "No requested extensions",
            ),
        );

        return;
    }

    const table = createElement(
        "table",
        "extensions-table",
    );

    const head = document.createElement("thead");
    const headRow = document.createElement("tr");

    for (const title of [
        "Name",
        "OID",
        "Critical",
        "Raw value",
    ]) {
        headRow.append(
            createElement("th", "", title),
        );
    }

    head.append(headRow);

    const body = document.createElement("tbody");

    for (const extension of extensions) {
        const row = document.createElement("tr");

        row.append(
            createElement(
                "td",
                "",
                extension.name || "Unknown extension",
            ),
        );

        row.append(
            createElement(
                "td",
                "",
                extension.oid,
            ),
        );

        row.append(
            createElement(
                "td",
                "",
                extension.critical ? "Yes" : "No",
            ),
        );

        row.append(
            createElement(
                "td",
                extension.value_hex
                    ? ""
                    : "empty-value",
                extension.value_hex || "Parsed",
            ),
        );

        body.append(row);
    }

    table.append(head, body);
    elements.extensionsContent.append(table);
}

function renderWarnings(warnings) {
    clearElement(elements.warningsList);

    if (
        !Array.isArray(warnings) ||
        warnings.length === 0
    ) {
        elements.warningsPanel.classList.add("hidden");

        return;
    }

    for (const warning of warnings) {
        elements.warningsList.append(
            createElement("li", "", warning),
        );
    }

    elements.warningsPanel.classList.remove("hidden");
}

function renderFindings(findings) {
    clearElement(elements.findingsContent);

    elements.findingsPanel.classList.remove("hidden");

    if (
        !Array.isArray(findings) ||
        findings.length === 0
    ) {
        elements.findingsContent.append(
            createElement(
                "div",
                "findings-success",
                "No obvious CSR quality issues were detected.",
            ),
        );

        return;
    }

    for (const finding of findings) {
        const severity =
            typeof finding.severity === "string"
                ? finding.severity
                : "info";

        const item = createElement(
            "article",
            `finding finding-${severity}`,
        );

        const header = createElement(
            "div",
            "finding-header",
        );

        header.append(
            createElement(
                "h3",
                "finding-title",
                finding.title || finding.code,
            ),
        );

        header.append(
            createElement(
                "span",
                "finding-severity",
                severity,
            ),
        );

        item.append(header);

        item.append(
            createElement(
                "p",
                "finding-message",
                finding.message,
            ),
        );

        elements.findingsContent.append(item);
    }
}

function renderResult(result) {
    lastResult = result;

    renderWarnings(result.warnings);
    renderFindings(result.findings);
    renderSubject(result.subject, result);
    renderSAN(result.subject_alternative_names);
    renderPublicKey(result.public_key);
    renderSignature(result.signature);
    renderRDNs(result.subject);
    renderExtensions(result.extensions);

    elements.rawJSON.textContent = JSON.stringify(
        result,
        null,
        2,
    );

    elements.resultRoot.classList.remove("hidden");
}

function hideResult() {
    lastResult = null;

    elements.resultRoot.classList.add("hidden");
    elements.warningsPanel.classList.add("hidden");
    elements.findingsPanel.classList.add("hidden");

    clearElement(elements.subjectSummary);
    clearElement(elements.sanContent);
    clearElement(elements.publicKeyContent);
    clearElement(elements.signatureContent);
    clearElement(elements.rdnContent);
    clearElement(elements.extensionsContent);
    clearElement(elements.findingsContent);
    

    elements.rawJSON.textContent = "";
}

function showError(message) {
    hideResult();

    elements.requestStatus.textContent = "";
    elements.errorMessage.textContent =
        message || "Unknown error";

    elements.errorPanel.classList.remove("hidden");
}

function hideError() {
    elements.errorPanel.classList.add("hidden");
    elements.errorMessage.textContent = "";
}

function setLoading(loading) {
    elements.parseButton.disabled = loading;
    elements.clearButton.disabled = loading;
    elements.fileInput.disabled = loading;

    elements.parseButton.textContent = loading
        ? "Inspecting…"
        : "Inspect CSR";

    if (loading) {
        elements.requestStatus.textContent =
            "Parsing certificate signing request…";
    }
}

function formatFileSize(size) {
    if (size < 1024) {
        return `${size} B`;
    }

    if (size < 1024 * 1024) {
        return `${(size / 1024).toFixed(1)} KiB`;
    }

    return `${(
        size /
        (1024 * 1024)
    ).toFixed(1)} MiB`;
}

async function loadCSRFile(file) {
    hideError();
    hideResult();

    if (!file) {
        return;
    }

    if (file.size === 0) {
        showError("The selected file is empty.");

        return;
    }

    if (file.size > MAX_CLIENT_FILE_SIZE) {
        showError(
            "The selected file is too large. " +
            "The maximum supported size is 1 MiB.",
        );

        return;
    }

    let content;

    try {
        content = await file.text();
    } catch {
        showError("Unable to read the selected file.");

        return;
    }

    if (!content.trim()) {
        showError(
            "The selected file contains no text.",
        );

        return;
    }

    elements.input.value = content;

    elements.selectedFileName.textContent =
        `${file.name} (${formatFileSize(file.size)})`;

    elements.selectedFileName.classList.remove("hidden");

    elements.requestStatus.textContent =
        "File loaded. Click Inspect CSR to parse it.";
}

function validatePEMHeader(input) {
    const trimmed = input.trim();

    const match = trimmed.match(
        /^-----BEGIN ([A-Z0-9][A-Z0-9 -]*)-----/,
    );

    if (!match) {
        return {
            valid: false,
            message:
                "The input does not contain a valid PEM header. " +
                "Expected -----BEGIN CERTIFICATE REQUEST-----.",
        };
    }

    const pemType = match[1];

    if (SUPPORTED_PEM_TYPES.has(pemType)) {
        return {
            valid: true,
            message: "",
        };
    }

    if (
        pemType === "CERTIFICATE" ||
        pemType === "X509 CERTIFICATE"
    ) {
        return {
            valid: false,
            message:
                "This appears to be an X.509 certificate, " +
                "not a certificate signing request. " +
                "Certificate inspection may be added " +
                "in a future version.",
        };
    }

    if (
        pemType === "PRIVATE KEY" ||
        pemType === "RSA PRIVATE KEY" ||
        pemType === "EC PRIVATE KEY" ||
        pemType === "ENCRYPTED PRIVATE KEY"
    ) {
        return {
            valid: false,
            message:
                "This appears to be a private key, not a CSR. " +
                "Do not upload or share private keys.",
        };
    }

    return {
        valid: false,
        message:
            `Unsupported PEM type: ${pemType}. ` +
            "Expected CERTIFICATE REQUEST or " +
            "NEW CERTIFICATE REQUEST.",
    };
}

async function extractErrorMessage(response) {
    const text = await response.text();

    if (!text) {
        return (
            `Request failed with status ` +
            `${response.status}.`
        );
    }

    let payload;

    try {
        payload = JSON.parse(text);
    } catch {
        return text;
    }

    if (
        typeof payload.error === "object" &&
        payload.error !== null &&
        typeof payload.error.message === "string"
    ) {
        return payload.error.message;
    }

    if (typeof payload.error === "string") {
        return payload.error;
    }

    if (typeof payload.message === "string") {
        return payload.message;
    }

    return (
        `Request failed with status ` +
        `${response.status}.`
    );
}

async function parseCSR() {
    const csrPEM = elements.input.value.trim();

    hideError();

    if (!csrPEM) {
        showError(
            "Paste a PEM-encoded CSR or select a CSR file.",
        );

        elements.input.focus();

        return;
    }

    const headerValidation = validatePEMHeader(csrPEM);

    if (!headerValidation.valid) {
        showError(headerValidation.message);

        return;
    }

    setLoading(true);

    const controller = new AbortController();

    const timeoutID = window.setTimeout(
        () => {
            controller.abort();
        },
        REQUEST_TIMEOUT_MS,
    );

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type":
                    "text/plain; charset=utf-8",
                "Accept": "application/json",
            },
            body: csrPEM,
            signal: controller.signal,
        });

        if (!response.ok) {
            const errorMessage =
                await extractErrorMessage(response);

            const requestID = response.headers.get(
                "X-Request-ID",
            );

            const message = requestID
                ? `${errorMessage}\n\nRequest ID: ${requestID}`
                : errorMessage;

            throw new Error(message);
        }

        const result = await response.json();

        renderResult(result);

        elements.requestStatus.textContent =
            "CSR inspected successfully.";

        elements.resultRoot.scrollIntoView({
            behavior: "smooth",
            block: "start",
        });
    } catch (error) {
        if (
            error instanceof DOMException &&
            error.name === "AbortError"
        ) {
            showError(
                "The request took too long. " +
                "Please try again.",
            );

            return;
        }

        /*
            fetch выбрасывает TypeError при сетевых проблемах:
            сервер недоступен, соединение потеряно,
            DNS не разрешился и т.д.
        */
        if (error instanceof TypeError) {
            showError(
                "Unable to connect to CSR Inspector. " +
                "Check your network connection and try again.",
            );

            return;
        }

        /*
            Сюда попадут нормальные ошибки API,
            которые мы сами создали через:

                throw new Error(errorMessage)
        */
        if (error instanceof Error) {
            showError(error.message);

            return;
        }

        showError("An unexpected error occurred.");
    } finally {
        window.clearTimeout(timeoutID);

        setLoading(false);
    }
}

function clearForm() {
    elements.input.value = "";
    elements.fileInput.value = "";

    elements.selectedFileName.textContent = "";
    elements.selectedFileName.classList.add("hidden");

    elements.requestStatus.textContent = "";

    hideError();
    hideResult();

    elements.input.focus();
}

async function copyRawJSON() {
    if (!lastResult) {
        return;
    }

    try {
        await navigator.clipboard.writeText(
            JSON.stringify(lastResult, null, 2),
        );

        const originalText =
            elements.copyJSONButton.textContent;

        elements.copyJSONButton.textContent = "Copied";

        window.setTimeout(() => {
            elements.copyJSONButton.textContent =
                originalText;
        }, 1200);
    } catch {
        elements.requestStatus.textContent =
            "Unable to copy JSON to clipboard.";
    }
}

elements.parseButton.addEventListener(
    "click",
    parseCSR,
);

elements.clearButton.addEventListener(
    "click",
    clearForm,
);

elements.copyJSONButton.addEventListener(
    "click",
    copyRawJSON,
);

elements.input.addEventListener(
    "keydown",
    (event) => {
        if (
            event.key === "Enter" &&
            (event.ctrlKey || event.metaKey)
        ) {
            event.preventDefault();

            parseCSR();
        }
    },
);

elements.dropZone.addEventListener(
    "click",
    () => {
        elements.fileInput.click();
    },
);

elements.dropZone.addEventListener(
    "keydown",
    (event) => {
        if (
            event.key === "Enter" ||
            event.key === " "
        ) {
            event.preventDefault();

            elements.fileInput.click();
        }
    },
);

elements.fileInput.addEventListener(
    "change",
    async () => {
        const files = elements.fileInput.files;

        if (!files || files.length === 0) {
            return;
        }

        await loadCSRFile(files[0]);
    },
);

for (const eventName of ["dragenter", "dragover"]) {
    elements.dropZone.addEventListener(
        eventName,
        (event) => {
            event.preventDefault();
            event.stopPropagation();

            elements.dropZone.classList.add(
                "drop-zone-active",
            );
        },
    );
}

for (const eventName of ["dragleave", "drop"]) {
    elements.dropZone.addEventListener(
        eventName,
        (event) => {
            event.preventDefault();
            event.stopPropagation();

            elements.dropZone.classList.remove(
                "drop-zone-active",
            );
        },
    );
}

elements.dropZone.addEventListener(
    "drop",
    async (event) => {
        const files = event.dataTransfer?.files;

        if (!files || files.length === 0) {
            return;
        }

        await loadCSRFile(files[0]);
    },
);

for (const eventName of ["dragover", "drop"]) {
    window.addEventListener(
        eventName,
        (event) => {
            event.preventDefault();
        },
    );
}