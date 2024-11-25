function toggleSSLFields() {
    const checkbox_http = document.getElementById('use_ssl_http');
    const checkbox_tcp = document.getElementById('use_ssl_tcp');
    const sslCertPath_http = document.getElementById('ssl_cert_path_http');
    const sslCertPath_tcp = document.getElementById('ssl_cert_path_tcp');
    const domainName_http = document.getElementById('domain_name_http');
    const domainName_tcp = document.getElementById('domain_name_tcp');

    if (checkbox_http.checked) {
        sslCertPath_http.setAttribute('required', true);
        domainName_http.setAttribute('required', true);
    } else {
        sslCertPath_http.removeAttribute('required');
        domainName_http.removeAttribute('required');
    }
    
    if (checkbox_tcp.checked) {
        sslCertPath_tcp.setAttribute('required', true);
        domainName_tcp.setAttribute('required', true);
    } else {
        sslCertPath_tcp.removeAttribute('required');
        domainName_tcp.removeAttribute('required');
    }
}

// Menambahkan event listener pada checkbox
document.getElementById('use_ssl_http').addEventListener('change', toggleSSLFields);
document.getElementById('use_ssl_tcp').addEventListener('change', toggleSSLFields);

document.addEventListener('DOMContentLoaded', function() {
    // Check HTTP SSL fields
    let useSSLHttp = document.getElementById('use_ssl_http');
    let sslFieldsHttp = document.getElementById('ssl_fields_http');
    if (useSSLHttp && useSSLHttp.checked) {
        sslFieldsHttp.style.display = 'block';
    }

    // Check TCP SSL fields
    let useSSLTcp = document.getElementById('use_ssl_tcp');
    let sslFieldsTcp = document.getElementById('ssl_fields_tcp');
    if (useSSLTcp && useSSLTcp.checked) {
        sslFieldsTcp.style.display = 'block';
    }
});

function validateIP(event) {
    const input = event.target.value;
    // Regex untuk memeriksa apakah input hanya terdiri dari angka dan titik
    const regex = /^[0-9.]*$/;

    // Jika input tidak sesuai dengan regex, hapus karakter terakhir
    if (!regex.test(input)) {
        event.target.value = input.slice(0, -1);
    }
}

function protocolFunction() {
    let protocol = document.getElementById("protocol").value;
    let protocolhttp = document.getElementById("protocol-http");
    let protocoltcp = document.getElementById("protocol-tcp");

    protocolhttp.style.display = 'none';
    protocoltcp.style.display = 'none';

    if (protocol === "http") {
        protocolhttp.style.display = 'block';
        protocoltcp.style.display = 'none';
    } else if (protocol === "tcp") {
        protocolhttp.style.display = 'none';
        protocoltcp.style.display = 'block';
    }
}

document.addEventListener('DOMContentLoaded', function () {
    protocolFunction();
});

document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('use_ssl_http').addEventListener('change', function () {
        let sslFieldsHttp = document.getElementById('ssl_fields_http');
        sslFieldsHttp.style.display = this.checked ? 'block' : 'none';
    });
    document.getElementById('use_ssl_tcp').addEventListener('change', function () {
        let sslFieldsTcp = document.getElementById('ssl_fields_tcp');
        sslFieldsTcp.style.display = this.checked ? 'block' : 'none';
    });
});

let lbMethod = ""; // Variabel global untuk menyimpan pilihan lb_method
let backendCounter = 1; // Counter mulai dari 1

function lbMethodFunction() {
    lbMethod = document.getElementById("lb_method").value;
    let weightField = document.getElementById("weight_field");
    let lb_fields = document.getElementById("lb_fields");
    let addBackendBtn = document.getElementById("addBackendBtn");

    // Tampilkan atau sembunyikan field berdasarkan pilihan lb_method
    if (lbMethod === "roundrobin") {
        weightField.style.display = "block";
        lb_fields.style.display = "block";
        addBackendBtn.style.display = "block";
    } else if (lbMethod === "source") { 
        weightField.style.display = "none";
        lb_fields.style.display = "block";
        addBackendBtn.style.display = "block";
    } else if (lbMethod === "leastconn") { 
        weightField.style.display = "none";
        lb_fields.style.display = "block";
        addBackendBtn.style.display = "block";
    } else {
        weightField.style.display = "none";
    }
}

document.addEventListener('DOMContentLoaded', function () {
    lbMethodFunction();
});

function addBackend() {
    // Menambah counter untuk label backend server
    backendCounter++;

    // Membuat elemen button untuk menghapus baris
    var deleteButton = document.createElement("button");
    deleteButton.setAttribute("type", "button");
    deleteButton.className = "btn btn-danger rounded-circle";
    deleteButton.style.cssText = "--bs-btn-padding-y: 2px; --bs-btn-padding-x: 2px; --bs-btn-font-size: .75rem; transform: translateY(-10px);";
    
    // Fungsi untuk menghapus row dan memperbarui nomor server
    deleteButton.addEventListener("click", function() {
        newRow.remove();
        updateServerNumbers();
    });

    // Membuat elemen ikon di dalam button
    var deleteIcon = document.createElement("i");
    deleteIcon.className = "mdi mdi-minus text-white";

    // Menambahkan ikon ke dalam button
    deleteButton.appendChild(deleteIcon);

    // Membuat elemen div untuk col-auto yang berisi button hapus
    var colAuto = document.createElement("div");
    colAuto.className = "col-auto";
    colAuto.appendChild(deleteButton);

    // Membuat elemen label dan input untuk nama backend server
    var labelName = document.createElement("label");
    labelName.setAttribute("for", "exampleInputName" + backendCounter);
    labelName.textContent = "Server " + backendCounter + " Name";
    var x = document.createElement("INPUT");
    x.setAttribute("type", "text");
    x.setAttribute("id", "exampleInputName" + backendCounter);
    x.setAttribute("placeholder", "Server " + backendCounter + " Name");
    x.setAttribute("name", "backend_server_names");
    // x.setAttribute("value", "{{ request.form['backend_server_names'] }}");
    x.setAttribute("required", "");
    x.className = "form-control";

    // Membuat elemen div untuk kolom nama backend server
    var colName = document.createElement("div");
    colName.className = "col";
    colName.appendChild(labelName);
    colName.appendChild(x);

    // Membuat elemen label dan input untuk IP backend server
    var labelIP = document.createElement("label");
    labelIP.setAttribute("for", "exampleInputName" + backendCounter);
    labelIP.textContent = "IP Address";
    var y = document.createElement("INPUT");
    y.setAttribute("type", "text");
    y.setAttribute("id", "exampleInputName" + backendCounter);
    y.setAttribute("placeholder", "IP Address");
    y.setAttribute("name", "backend_server_ips");
    y.setAttribute("oninput", "validateIP(event)");
    // y.setAttribute("value", "{{ request.form['backend_server_ips'] }}");
    y.setAttribute("required", "");
    y.className = "form-control";

    // Membuat elemen div untuk kolom IP backend server
    var colIP = document.createElement("div");
    colIP.className = "col";
    colIP.appendChild(labelIP);
    colIP.appendChild(y);

    // Membuat elemen label dan input untuk port backend server
    var labelPort = document.createElement("label");
    labelPort.setAttribute("for", "exampleInputName" + backendCounter);
    labelPort.textContent = "Port";
    var z = document.createElement("INPUT");
    z.setAttribute("type", "text");
    z.setAttribute("id", "exampleInputName" + backendCounter);
    z.setAttribute("placeholder", "Port");
    z.setAttribute("name", "backend_server_ports");
    z.setAttribute("oninput", "validateIP(event)");
    // z.setAttribute("value", "{{ request.form['backend_server_ports'] }}");
    z.setAttribute("required", "");
    z.className = "form-control";

    // Membuat elemen div untuk kolom port backend server
    var colPort = document.createElement("div");
    colPort.className = "col-2";
    colPort.appendChild(labelPort);
    colPort.appendChild(z);

    // Membuat row baru dan menambahkan col-auto dan kolom ke dalamnya
    var newRow = document.createElement("div");
    newRow.className = "form-group row g-3 align-items-end";
    newRow.appendChild(colAuto);  // Tambahkan col-auto (button hapus) sebelum kolom nama backend server
    newRow.appendChild(colName);
    newRow.appendChild(colIP);
    newRow.appendChild(colPort);

    // Jika lb_method adalah roundrobin, tambahkan input untuk weight
    if (lbMethod === "roundrobin") {
        var labelWeight = document.createElement("label");
        labelWeight.setAttribute("for", "exampleInputName" + backendCounter);
        labelWeight.textContent = "Weight";
        var w = document.createElement("INPUT");
        w.setAttribute("type", "text");
        w.setAttribute("id", "exampleInputName" + backendCounter);
        w.setAttribute("placeholder", "Weight");
        w.setAttribute("name", "backend_server_weights");
        w.setAttribute("oninput", "validateIP(event)");
        w.setAttribute("value", "1");
        w.className = "form-control";

        var colWeight = document.createElement("div");
        colWeight.className = "col-1";
        colWeight.appendChild(labelWeight);
        colWeight.appendChild(w);

        newRow.appendChild(colWeight);
    }

    // Menambahkan row baru ke dalam container
    var container = document.getElementById("lb_fields");
    container.appendChild(newRow);
}

// Fungsi untuk memperbarui nomor server setelah penghapusan
function updateServerNumbers() {
    var rows = document.querySelectorAll("#lb_fields .form-group.row");
    backendCounter = 0;
    rows.forEach(function(row, index) {
        backendCounter++;
        var labelName = row.querySelector(".col label");
        var inputName = row.querySelector(".col input");
        labelName.textContent = "Server " + backendCounter + " Name";
        inputName.setAttribute("placeholder", "Server " + backendCounter + " Name");
    });
}