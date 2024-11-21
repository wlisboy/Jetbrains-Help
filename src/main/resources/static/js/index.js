$(document).ready(function() {
    // Set default headers for AJAX requests
    $.ajaxSetup({
        headers: {
            'Content-Type': 'application/json'
        }
    });

    // Function to handle submission of license information
    window.submitLicenseInfo = function () {
        let licenseInfo = {
            licenseeName: $('#licenseeName').val(),
            assigneeName: $('#assigneeName').val(),
            expiryDate: $('#expiryDate').val()
        };
        localStorage.setItem('licenseInfo', JSON.stringify(licenseInfo));
        $('#mask, #form').hide();
    };

    // Function to handle search input
    $('#search').on('input', function(e) {
        $("#product-list").load('/search?search=' + e.target.value);
    });

    // Function to show license form
    window.showLicenseForm = function () {
        let licenseInfo = JSON.parse(localStorage.getItem('licenseInfo'));
        $('#licenseeName').val(licenseInfo?.licenseeName || 'username');
        $('#assigneeName').val(licenseInfo?.assigneeName || 'username');
        $('#expiryDate').val(licenseInfo?.expiryDate || '2099-12-31');
        $('#mask, #form').show();
    };

    // Function to show VM options
    window.showVmoptins = function () {
        const text = "-javaagent:/(Your Path)/ja-netfilter/ja-netfilter.jar\n" +
        "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED\n" +
        "--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED";
        copyText(text)
            .then(() => alert("已复制到剪贴板"))
            .catch(() => alert("复制失败，请检查网络"));
    };

    // Function to copy license
    window.copyLicense = async function (e) {
        while (localStorage.getItem('licenseInfo') === null) {
            $('#mask, #form').show();
            await new Promise(r => setTimeout(r, 1000));
        }
        let licenseInfo = JSON.parse(localStorage.getItem('licenseInfo'));
        let productCode = $(e).closest('.card').data('productCodes');
        let data = {
            "licenseName": licenseInfo.licenseeName,
            "assigneeName": licenseInfo.assigneeName,
            "expiryDate": licenseInfo.expiryDate,
            "productCode": productCode,
        };
        $.post('/generateLicense', JSON.stringify(data))
            .then(response => {
                copyText(response)
                    .then(() => {
                        alert("已复制成功");
                    })
                    .catch(() => {
                        alert("系统不支持复制功能,或者当前非SSL访问,若为Local环境,请使用127.0.0.1或者localhost访问.");
                    });
            });
    };

// Function to copy text to clipboard
    const copyText = async (val) => {
        if (navigator.clipboard && navigator.permissions) {
            return navigator.clipboard.writeText(val);
        } else {
            console.log(val);
            const textArea = document.createElement('textarea')
            textArea.value = val
            // 使text area不在viewport，同时设置不可见
            document.body.appendChild(textArea)
            textArea.focus()
            textArea.select()
            return new Promise((res, rej) => {
                document.execCommand('copy') ? res() : rej()
                textArea.remove()
            })
        }
    };

});
