function validateIP(event) {
    const input = event.target.value;
    // Regex untuk memeriksa apakah input hanya terdiri dari angka dan titik
    const regex = /^[0-9.]*$/;

    // Jika input tidak sesuai dengan regex, hapus karakter terakhir
    if (!regex.test(input)) {
        event.target.value = input.slice(0, -1);
    }
}

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
    // Fungsi untuk menampilkan atau menyembunyikan field SSL berdasarkan checkbox
    function toggleSSLField(checkboxId, sslFieldId) {
        let checkbox = document.getElementById(checkboxId);
        let sslField = document.getElementById(sslFieldId);
        sslField.style.display = checkbox.checked ? 'block' : 'none';
    }

    // Cek status checkbox SSL dan atur tampilan awal dari ssl_fields_http
    toggleSSLField('use_ssl_http', 'ssl_fields_http');

    // Cek status checkbox SSL dan atur tampilan awal dari ssl_fields_tcp
    toggleSSLField('use_ssl_tcp', 'ssl_fields_tcp');

    // Tambahkan event listener untuk perubahan pada checkbox use_ssl_http
    document.getElementById('use_ssl_http').addEventListener('change', function () {
        toggleSSLField('use_ssl_http', 'ssl_fields_http');
    });

    // Tambahkan event listener untuk perubahan pada checkbox use_ssl_tcp
    document.getElementById('use_ssl_tcp').addEventListener('change', function () {
        toggleSSLField('use_ssl_tcp', 'ssl_fields_tcp');
    });
});


function deleterow(deleteButton) {
    let row = deleteButton.closest('.form-group');  // Find the closest form-group row
    row.remove();  // Remove the row
    updateServerNumbers();  // Update the server numbers (you can define this function as needed)
}


let lbMethod = ""; // Variabel global untuk menyimpan pilihan lb_method
let backendCounter = parseInt(document.getElementById('lb_fields').getAttribute('data-count-server')) || 0;

function lbMethodFunction() {
    lbMethod = document.getElementById("lb_method").value;
    let weightFields = document.querySelectorAll("#lb_fields .col-1");
    let lb_fields = document.getElementById("lb_fields");
    let addBackendBtn = document.getElementById("addBackendBtn");

    if (lbMethod === "roundrobin") {
        weightFields.forEach(function (field) {
            field.style.display = "block";
        });
    } else {
        // Hapus nilai input di bidang Weight sebelum menyembunyikannya
        weightFields.forEach(function (field) {
            field.querySelector('input').value = "1";
            field.style.display = "none";
        });
    }

    lb_fields.style.display = "block";
    addBackendBtn.style.display = "block";
}

document.addEventListener('DOMContentLoaded', function(){
    lbMethodFunction();
});

function addBackend() {
    // Menambah counter untuk label backend server
    backendCounter++;

    var deleteButton = document.createElement("button");
    deleteButton.setAttribute("type", "button");
    deleteButton.className = "btn btn-danger rounded-circle";
    deleteButton.style.cssText = "--bs-btn-padding-y: 2px; --bs-btn-padding-x: 2px; --bs-btn-font-size: .75rem; transform: translateY(-10px);";

    // Membuat elemen ikon di dalam button
    var deleteIcon = document.createElement("i");
    deleteIcon.className = "mdi mdi-minus text-white";

    // Menambahkan ikon ke dalam button
    deleteButton.appendChild(deleteIcon);

    // Fungsi untuk menghapus row dan memperbarui nomor server
    deleteButton.addEventListener("click", function() {
        newRow.remove();
        updateServerNumbers();
    });

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
    x.setAttribute("required", "");
    x.className = "form-control";

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
    y.setAttribute("required", "");
    y.className = "form-control";

    // Membuat elemen label dan input untuk port backend server
    var labelPort = document.createElement("label");
    labelPort.setAttribute("for", "exampleInputName" + backendCounter);
    labelPort.textContent = "Port";
    var z = document.createElement("INPUT");
    z.setAttribute("type", "number");
    z.setAttribute("id", "exampleInputName" + backendCounter);
    z.setAttribute("placeholder", "Port");
    z.setAttribute("name", "backend_server_ports");
    z.setAttribute("oninput", "validateIP(event)");
    z.setAttribute("required", "");
    z.className = "form-control";

    // Membuat elemen div untuk setiap kolom dan menambahkan label dan input ke dalamnya
    var colName = document.createElement("div");
    colName.className = "col";
    colName.appendChild(labelName);
    colName.appendChild(x);

    var colIP = document.createElement("div");
    colIP.className = "col";
    colIP.appendChild(labelIP);
    colIP.appendChild(y);

    var colPort = document.createElement("div");
    colPort.className = "col-2";
    colPort.appendChild(labelPort);
    colPort.appendChild(z);

    // Membuat row baru dan menambahkan kolom ke dalamnya
    var newRow = document.createElement("div");
    newRow.className = "form-group row g-3 align-items-end";
    newRow.appendChild(colAuto);
    newRow.appendChild(colName);
    newRow.appendChild(colIP);
    newRow.appendChild(colPort);

    // Jika lb_method adalah roundrobin, tambahkan input untuk weight
    if (lbMethod === "roundrobin") {
        var labelWeight = document.createElement("label");
        labelWeight.setAttribute("for", "exampleInputName" + backendCounter);
        labelWeight.textContent = "Weight";
        
        var w = document.createElement("INPUT");
        w.setAttribute("type", "number");
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