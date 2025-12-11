document.addEventListener('DOMContentLoaded', () => {
    // User form toggling and editing

    const toggleBtn = document.getElementById("toggleFormBtn");
    const form = document.getElementById("addUserForm");
    const userForm = document.getElementById("userForm");
    const formSubmitBtn = document.getElementById("formSubmitBtn");
    const cancelEditBtn = document.getElementById("cancelEditBtn");
    const userIdInput = document.getElementById("user_id");
    const usernameInput = document.getElementById("username");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const passwordRow = document.getElementById("passwordRow");
    const roleSelect = document.getElementById("role");
    const imageInput = document.getElementById("image");
    const avatarPreview = document.getElementById("avatarPreview");

    function resetForm() {
        userForm.action = "/add_user";
        formSubmitBtn.textContent = "Add User";
        cancelEditBtn.style.display = "none";
        userIdInput.value = "";
        usernameInput.value = "";
        emailInput.value = "";
        passwordInput.value = "";
        passwordInput.required = true;
        roleSelect.value = "";
        imageInput.value = "";
        avatarPreview.src = "";
        avatarPreview.style.display = "none";
    }

    if (toggleBtn) {
        toggleBtn.addEventListener("click", () => {
            if (form.style.display === "none" || !form.style.display) {
                resetForm();
                form.style.display = "block";
                toggleBtn.textContent = "− Close Form";
            } else {
                form.style.display = "none";
                toggleBtn.textContent = "+ Add New User";
            }
        });
    }

    if (cancelEditBtn) {
        cancelEditBtn.addEventListener("click", () => {
            resetForm();
            form.style.display = "none";
            toggleBtn.textContent = "+ Add New User";
        });
    }

    document.querySelectorAll('.btn-action.edit').forEach(button => {
        button.addEventListener('click', (e) => {
            e.preventDefault();
            const userId = button.getAttribute('data-id');
            const username = button.getAttribute('data-username');
            const email = button.getAttribute('data-email');
            const role = button.getAttribute('data-role');
            const image = button.getAttribute('data-image');

            userIdInput.value = userId;
            usernameInput.value = username;
            emailInput.value = email;
            roleSelect.value = role;
            passwordInput.value = "";
            passwordInput.required = false;

            avatarPreview.src = image;
            avatarPreview.style.display = "block";

            userForm.action = `/edit_user/${userId}`;
            formSubmitBtn.textContent = "Update User";
            cancelEditBtn.style.display = "inline-block";
            form.style.display = "block";
            toggleBtn.textContent = "− Close Form";
        });
    });

    if (imageInput) {
        imageInput.addEventListener("change", () => {
            const file = imageInput.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    avatarPreview.src = e.target.result;
                    avatarPreview.style.display = "block";
                };
                reader.readAsDataURL(file);
            } else {
                avatarPreview.src = "";
                avatarPreview.style.display = "none";
            }
        });
    }

    // Sidebar toggle

    const openBtn = document.querySelector('.open-toggle');
    const closeBtn = document.querySelector('.close-toggle');
    const sidebar = document.querySelector('.sideBar');

    if (closeBtn) closeBtn.style.display = 'none';

    if (openBtn) {
        openBtn.addEventListener('click', () => {
            sidebar.classList.add('open');
            if (closeBtn) closeBtn.style.display = 'block';
            openBtn.style.display = 'none';
        });
    }

    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            sidebar.classList.remove('open');
            closeBtn.style.display = 'none';
            if (openBtn) openBtn.style.display = 'block';
        });
    }
});
