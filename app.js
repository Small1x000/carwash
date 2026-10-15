/**
 * CarWash Tracker - Управление автомойкой (SPA)
 * Работает прямо в браузере, без внешних серверов, сохраняет все данные в localStorage
 */

const STORAGE_KEY = 'carwash_tracker_db_v1';

// Категории кузова и коэффициенты цен
const CATEGORY_MULTIPLIERS = {
    sedan: 1.0,
    crossover: 1.25,
    suv: 1.5,
    minivan: 1.8
};

// Начальные данные по умолчанию (если база пустая)
const DEFAULT_STATE = {
    ownerPassword: '1234',
    boxes: [
        { id: 1, name: 'Бокс 1' },
        { id: 2, name: 'Бокс 2' },
        { id: 3, name: 'Бокс 3' }
    ],
    workers: [
        { id: 'w1', name: 'Азамат', percent: 30 },
        { id: 'w2', name: 'Даулет', percent: 30 },
        { id: 'w3', name: 'Ерлан', percent: 30 }
    ],
    services: [
        { id: 's1', name: 'Кузов (бесконтактная)', basePrice: 2000 },
        { id: 's2', name: 'Салон (пылесос, влажная)', basePrice: 1500 },
        { id: 's3', name: 'Комплекс (кузов + салон)', basePrice: 3200 },
        { id: 's4', name: 'Горячий воск', basePrice: 1000 },
        { id: 's5', name: 'Чернение резины', basePrice: 500 },
        { id: 's6', name: 'Химчистка багажника', basePrice: 2500 }
    ],
    orders: [
        {
            id: 101,
            carPlate: '777 AAA 01',
            carModel: 'Toyota Camry 70',
            category: 'sedan',
            boxId: 1,
            workerId: 'w1',
            phone: '+7 777 123 45 67',
            services: ['s3', 's5'],
            totalPrice: 3700,
            status: 'in-progress',
            paymentMethod: null,
            createdAt: new Date().toISOString(),
            paidAt: null
        },
        {
            id: 102,
            carPlate: '555 KZ 02',
            carModel: 'BMW X5',
            category: 'suv',
            boxId: 2,
            workerId: 'w2',
            phone: '',
            services: ['s1'],
            totalPrice: 3000,
            status: 'ready',
            paymentMethod: null,
            createdAt: new Date(Date.now() - 3600000).toISOString(),
            paidAt: null
        }
    ]
};

class CarWashApp {
    constructor() {
        this.currentRole = 'worker'; // 'worker' или 'owner'
        this.activePaymentOrderId = null;
        this.loadDatabase();
        this.initDOM();
        this.applyRoleUI();
        this.renderAll();
    }

    // Загрузка данных из локального хранилища
    loadDatabase() {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            try {
                this.db = JSON.parse(stored);
            } catch (e) {
                console.error('Ошибка чтения данных, сброс на дефолт', e);
                this.db = JSON.parse(JSON.stringify(DEFAULT_STATE));
            }
        } else {
            this.db = JSON.parse(JSON.stringify(DEFAULT_STATE));
            this.saveDatabase();
        }
    }

    saveDatabase() {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(this.db));
    }

    initDOM() {
        // Текущая дата смены
        const options = { day: 'numeric', month: 'long', year: 'numeric' };
        document.getElementById('shiftDate').textContent = new Date().toLocaleDateString('ru-RU', options);
    }

    // Ролевая модель и UI
    applyRoleUI() {
        const badge = document.getElementById('currentRoleBadge');
        if (this.currentRole === 'owner') {
            document.body.classList.remove('role-worker');
            document.body.classList.add('role-owner');
            badge.textContent = '👑 Кабинет: Владелец';
            badge.style.background = '#fef3c7';
            badge.style.color = '#b45309';
        } else {
            document.body.classList.remove('role-owner');
            document.body.classList.add('role-worker');
            badge.textContent = '🧽 Кабинет: Администратор / Рабочий';
            badge.style.background = '#eff6ff';
            badge.style.color = '#2563eb';
        }
    }

    openAuthModal() {
        document.getElementById('authModal').classList.add('open');
        this.hideOwnerLoginForm();
    }

    closeAuthModal() {
        document.getElementById('authModal').classList.remove('open');
    }

    loginAsWorker() {
        this.currentRole = 'worker';
        this.applyRoleUI();
        this.closeAuthModal();
        this.switchTab('activeOrders');
        alert('Вы переключились в рабочий кабинет смены.');
    }

    showOwnerLoginForm() {
        document.getElementById('ownerPasswordBlock').style.display = 'block';
        document.getElementById('ownerPasswordInput').focus();
    }

    hideOwnerLoginForm() {
        document.getElementById('ownerPasswordBlock').style.display = 'none';
        document.getElementById('ownerPasswordInput').value = '';
    }

    submitOwnerLogin() {
        const inputPass = document.getElementById('ownerPasswordInput').value;
        // Проверка пароля владельца или аварийного мастер-кода
        if (inputPass === this.db.ownerPassword || inputPass === '9999') {
            this.currentRole = 'owner';
            this.applyRoleUI();
            this.closeAuthModal();
            alert('Успешный вход в кабинет Владельца!');
        } else {
            alert('Неверный пароль владельца! Если забыли пароль, нажмите «Забыли пароль?» ниже.');
        }
    }

    forgotPasswordPrompt() {
        const recoveryCode = prompt('Для сброса пароля введите мастер-код восстановления (по умолчанию: 9999):');
        if (recoveryCode === '9999') {
            this.db.ownerPassword = '1234';
            this.saveDatabase();
            alert('Пароль успешно сброшен на стандартный: 1234\nТеперь можете войти с паролем 1234.');
            document.getElementById('ownerPasswordInput').value = '1234';
        } else if (recoveryCode !== null) {
            alert('Неверный мастер-код восстановления.');
        }
    }

    changeOwnerPassword() {
        const newPass = document.getElementById('newOwnerPassword').value.trim();
        if (!newPass) {
            alert('Введите новый пароль!');
            return;
        }
        this.db.ownerPassword = newPass;
        this.saveDatabase();
        document.getElementById('newOwnerPassword').value = '';
        alert('Пароль владельца успешно изменен!');
    }

    // Навигация по вкладкам
    switchTab(tabId) {
        if (['finance', 'settings'].includes(tabId) && this.currentRole !== 'owner') {
            this.openAuthModal();
            this.showOwnerLoginForm();
            return;
        }

        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabId);
        });

        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `tab-${tabId}`);
        });

        if (tabId === 'finance') this.renderFinance();
        if (tabId === 'history') this.renderHistory();
        if (tabId === 'activeOrders') this.renderActiveOrders();
    }

    // Рендер всех частей
    renderAll() {
        this.renderBoxesAndSelects();
        this.renderServicesCheckboxes();
        this.renderActiveOrders();
        this.renderHistory();
        this.renderFinance();
        this.renderSettings();
    }

    renderBoxesAndSelects() {
        // Контейнер боксов
        const container = document.getElementById('boxesContainer');
        const boxSelect = document.getElementById('orderBox');
        container.innerHTML = '';
        boxSelect.innerHTML = '';

        this.db.boxes.forEach(box => {
            // Найти активный заказ в этом боксе
            const activeOrder = this.db.orders.find(o => o.boxId === box.id && (o.status === 'in-progress' || o.status === 'ready'));

            const isBusy = !!activeOrder;
            const card = document.createElement('div');
            card.className = `box-card ${isBusy ? 'busy' : 'free'}`;
            card.innerHTML = `
                <div class="box-header">
                    <h3>${box.name}</h3>
                    <span class="box-status ${isBusy ? 'busy' : 'free'}">${isBusy ? 'Занят' : 'Свободен'}</span>
                </div>
                ${isBusy ? `
                    <div class="box-car-info">${activeOrder.carPlate}</div>
                    <div class="box-details">${activeOrder.carModel || 'Авто'} • ${this.getWorkerName(activeOrder.workerId)}</div>
                    <div style="margin-top: 0.5rem;">
                        <span class="status-pill ${activeOrder.status}">
                            ${activeOrder.status === 'in-progress' ? '🚿 Моется' : '✅ Помыта'}
                        </span>
                    </div>
                ` : `
                    <div class="text-muted" style="margin: 1rem 0;">Бокс готов к приему авто</div>
                    <button class="btn btn-outline btn-sm" onclick="app.quickAssignBox(${box.id})">+ Запустить авто</button>
                `}
            `;
            container.appendChild(card);

            // Селект для формы
            const option = document.createElement('option');
            option.value = box.id;
            option.textContent = `${box.name} ${isBusy ? '(Занят)' : '(Свободен)'}`;
            boxSelect.appendChild(option);
        });

        // Селект мойщиков
        const workerSelect = document.getElementById('orderWorker');
        workerSelect.innerHTML = '';
        this.db.workers.forEach(w => {
            const option = document.createElement('option');
            option.value = w.id;
            option.textContent = `${w.name} (${w.percent}%)`;
            workerSelect.appendChild(option);
        });
    }

    quickAssignBox(boxId) {
        this.switchTab('newOrder');
        document.getElementById('orderBox').value = boxId;
    }

    renderServicesCheckboxes() {
        const container = document.getElementById('servicesCheckboxes');
        container.innerHTML = '';

        this.db.services.forEach(s => {
            const label = document.createElement('label');
            label.className = 'service-checkbox-card';
            label.innerHTML = `
                <input type="checkbox" name="services" value="${s.id}" onchange="app.recalculateTotal()">
                <div>
                    <div><strong>${s.name}</strong></div>
                    <small class="text-muted">базовая: ${s.basePrice} ₸</small>
                </div>
            `;
            container.appendChild(label);
        });
    }

    recalculateTotal() {
        const category = document.getElementById('carCategory').value;
        const multiplier = CATEGORY_MULTIPLIERS[category] || 1.0;

        const checkedServices = Array.from(document.querySelectorAll('input[name="services"]:checked')).map(el => el.value);

        let total = 0;
        checkedServices.forEach(sid => {
            const service = this.db.services.find(s => s.id === sid);
            if (service) {
                total += Math.round(service.basePrice * multiplier);
            }
        });

        document.getElementById('calculatedPrice').textContent = `${total.toLocaleString()} ₸`;
        return total;
    }

    createOrder(event) {
        event.preventDefault();

        const carPlate = document.getElementById('carPlate').value.trim().toUpperCase();
        const carModel = document.getElementById('carModel').value.trim();
        const category = document.getElementById('carCategory').value;
        const boxId = parseInt(document.getElementById('orderBox').value);
        const workerId = document.getElementById('orderWorker').value;
        const phone = document.getElementById('clientPhone').value.trim();

        const selectedServices = Array.from(document.querySelectorAll('input[name="services"]:checked')).map(el => el.value);

        if (selectedServices.length === 0) {
            alert('Пожалуйста, выберите хотя бы одну услугу!');
            return;
        }

        const totalPrice = this.recalculateTotal();

        const newOrder = {
            id: Date.now(),
            carPlate,
            carModel,
            category,
            boxId,
            workerId,
            phone,
            services: selectedServices,
            totalPrice,
            status: 'in-progress',
            paymentMethod: null,
            createdAt: new Date().toISOString(),
            paidAt: null
        };

        this.db.orders.unshift(newOrder);
        this.saveDatabase();

        // Сброс формы
        event.target.reset();
        this.recalculateTotal();

        this.renderAll();
        this.switchTab('activeOrders');
    }

    renderActiveOrders() {
        const tbody = document.getElementById('activeOrdersTableBody');
        tbody.innerHTML = '';

        const activeList = this.db.orders.filter(o => o.status === 'in-progress' || o.status === 'ready');
        document.getElementById('activeCount').textContent = activeList.length;

        if (activeList.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#94a3b8; padding:2rem;">Сейчас нет машин в боксах. Нажмите «Оформить заезд».</td></tr>`;
            return;
        }

        activeList.forEach((order, index) => {
            const box = this.db.boxes.find(b => b.id === order.boxId);
            const worker = this.db.workers.find(w => w.id === order.workerId);
            const serviceNames = order.services.map(sid => {
                const s = this.db.services.find(srv => srv.id === sid);
                return s ? s.name : '';
            }).filter(Boolean).join(', ');

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${index + 1}</strong></td>
                <td>
                    <strong>${order.carPlate}</strong>
                    <div class="text-muted" style="font-size:0.8rem;">${order.carModel || 'Не указана'}</div>
                </td>
                <td>${box ? box.name : '—'}</td>
                <td style="max-width:250px;">${serviceNames}</td>
                <td>${worker ? worker.name : '—'}</td>
                <td><strong>${order.totalPrice.toLocaleString()} ₸</strong></td>
                <td>
                    <span class="status-pill ${order.status}">
                        ${order.status === 'in-progress' ? '🚿 В работе' : '✅ Готово'}
                    </span>
                </td>
                <td>
                    <div style="display: flex; gap: 0.4rem;">
                        ${order.status === 'in-progress' ? `
                            <button class="btn btn-outline btn-sm" onclick="app.setOrderReady(${order.id})" title="Отметить как готово">
                                ✅ Готово
                            </button>
                        ` : ''}
                        <button class="btn btn-success btn-sm" onclick="app.openPaymentModal(${order.id})">
                            💳 Оплата
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    setOrderReady(orderId) {
        const order = this.db.orders.find(o => o.id === orderId);
        if (order) {
            order.status = 'ready';
            this.saveDatabase();
            this.renderAll();
        }
    }

    openPaymentModal(orderId) {
        const order = this.db.orders.find(o => o.id === orderId);
        if (!order) return;

        this.activePaymentOrderId = orderId;
        document.getElementById('payOrderId').textContent = order.carPlate;
        document.getElementById('payOrderInfo').textContent = `${order.carModel || ''} | Мойщик: ${this.getWorkerName(order.workerId)}`;
        document.getElementById('payTotalAmount').textContent = `${order.totalPrice.toLocaleString()} ₸`;

        document.getElementById('paymentModal').classList.add('open');
    }

    closePaymentModal() {
        document.getElementById('paymentModal').classList.remove('open');
        this.activePaymentOrderId = null;
    }

    confirmPayment() {
        if (!this.activePaymentOrderId) return;

        const order = this.db.orders.find(o => o.id === this.activePaymentOrderId);
        if (order) {
            const method = document.querySelector('input[name="payMethod"]:checked').value;
            order.status = 'paid';
            order.paymentMethod = method;
            order.paidAt = new Date().toISOString();

            this.saveDatabase();
            this.closePaymentModal();
            this.renderAll();
            alert(`Заказ ${order.carPlate} успешно закрыт и оплачен!`);
        }
    }

    renderHistory() {
        const tbody = document.getElementById('historyTableBody');
        tbody.innerHTML = '';

        const dateFilter = document.getElementById('historyDateFilter').value;

        const historyList = this.db.orders.filter(o => {
            if (o.status !== 'paid') return false;
            if (dateFilter) {
                const orderDate = new Date(o.paidAt || o.createdAt).toISOString().split('T')[0];
                return orderDate === dateFilter;
            }
            return true;
        });

        if (historyList.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#94a3b8; padding:2rem;">В истории пока нет закрытых заказов за выбранную дату.</td></tr>`;
            return;
        }

        historyList.forEach(order => {
            const worker = this.db.workers.find(w => w.id === order.workerId);
            const dateStr = new Date(order.paidAt || order.createdAt).toLocaleString('ru-RU', {
                day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
            });

            const methodNames = {
                cash: '💵 Наличные',
                card: '💳 Карта',
                transfer: '📱 Kaspi/Перевод'
            };

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${dateStr}</td>
                <td><strong>${order.carPlate}</strong></td>
                <td>${order.carModel || '—'}</td>
                <td style="font-size:0.85rem;">${order.services.length} услуг(и)</td>
                <td>${worker ? worker.name : '—'}</td>
                <td>${methodNames[order.paymentMethod] || 'Оплачено'}</td>
                <td><strong>${order.totalPrice.toLocaleString()} ₸</strong></td>
                <td><span class="status-pill paid">Выполнен</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    resetHistoryFilter() {
        document.getElementById('historyDateFilter').value = '';
        this.renderHistory();
    }

    // Финансы и аналитика (для Владельца)
    renderFinance() {
        const todayStr = new Date().toISOString().split('T')[0];
        const currentMonth = new Date().getMonth();
        const currentYear = new Date().getFullYear();

        let todayIncome = 0;
        let todayCount = 0;
        let monthIncome = 0;
        let monthCount = 0;
        let totalSalaries = 0;

        const workerStats = {};
        this.db.workers.forEach(w => {
            workerStats[w.id] = { name: w.name, percent: w.percent, count: 0, salary: 0 };
        });

        this.db.orders.forEach(o => {
            if (o.status !== 'paid') return;

            const orderDate = new Date(o.paidAt || o.createdAt);
            const dateStr = orderDate.toISOString().split('T')[0];

            // Сегодня
            if (dateStr === todayStr) {
                todayIncome += o.totalPrice;
                todayCount += 1;
            }

            // Месяц
            if (orderDate.getMonth() === currentMonth && orderDate.getFullYear() === currentYear) {
                monthIncome += o.totalPrice;
                monthCount += 1;
            }

            // Зарплаты
            if (workerStats[o.workerId]) {
                workerStats[o.workerId].count += 1;
                const earned = Math.round(o.totalPrice * (workerStats[o.workerId].percent / 100));
                workerStats[o.workerId].salary += earned;
                totalSalaries += earned;
            }
        });

        document.getElementById('statTodayIncome').textContent = `${todayIncome.toLocaleString()} ₸`;
        document.getElementById('statTodayCount').textContent = `${todayCount} вымытых авто`;

        document.getElementById('statMonthIncome').textContent = `${monthIncome.toLocaleString()} ₸`;
        document.getElementById('statMonthCount').textContent = `${monthCount} вымытых авто`;

        document.getElementById('statSalaryFund').textContent = `${totalSalaries.toLocaleString()} ₸`;
        document.getElementById('statNetIncome').textContent = `${(monthIncome - totalSalaries).toLocaleString()} ₸`;

        // Таблица выработки
        const salaryTbody = document.getElementById('workerSalaryTableBody');
        salaryTbody.innerHTML = '';
        Object.values(workerStats).forEach(stat => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${stat.name}</strong></td>
                <td>${stat.count} авто</td>
                <td>${stat.percent}%</td>
                <td><strong style="color:var(--primary);">${stat.salary.toLocaleString()} ₸</strong></td>
            `;
            salaryTbody.appendChild(tr);
        });
    }

    renderSettings() {
        // Список сотрудников
        const wList = document.getElementById('workersList');
        wList.innerHTML = '';
        this.db.workers.forEach(w => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span><strong>${w.name}</strong> (${w.percent}% от чека)</span>
                <button class="btn btn-outline btn-sm" onclick="app.removeWorker('${w.id}')" style="color:red;">Удалить</button>
            `;
            wList.appendChild(li);
        });

        // Список услуг
        const sList = document.getElementById('servicesList');
        sList.innerHTML = '';
        this.db.services.forEach(s => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span><strong>${s.name}</strong> — ${s.basePrice} ₸</span>
                <button class="btn btn-outline btn-sm" onclick="app.removeService('${s.id}')" style="color:red;">Удалить</button>
            `;
            sList.appendChild(li);
        });
    }

    addWorker(e) {
        e.preventDefault();
        const name = document.getElementById('newWorkerName').value.trim();
        const percent = parseInt(document.getElementById('newWorkerPercent').value);

        this.db.workers.push({ id: 'w_' + Date.now(), name, percent });
        this.saveDatabase();
        e.target.reset();
        this.renderAll();
    }

    removeWorker(id) {
        if (!confirm('Удалить этого сотрудника?')) return;
        this.db.workers = this.db.workers.filter(w => w.id !== id);
        this.saveDatabase();
        this.renderAll();
    }

    addService(e) {
        e.preventDefault();
        const name = document.getElementById('newServiceName').value.trim();
        const basePrice = parseInt(document.getElementById('newServicePrice').value);

        this.db.services.push({ id: 's_' + Date.now(), name, basePrice });
        this.saveDatabase();
        e.target.reset();
        this.renderAll();
    }

    removeService(id) {
        if (!confirm('Удалить эту услугу?')) return;
        this.db.services = this.db.services.filter(s => s.id !== id);
        this.saveDatabase();
        this.renderAll();
    }

    getWorkerName(id) {
        const w = this.db.workers.find(item => item.id === id);
        return w ? w.name : '—';
    }

    // Резервное копирование и экспорт
    exportDatabase() {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.db, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `carwash_backup_${new Date().toISOString().split('T')[0]}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    }

    importDatabase(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const parsed = JSON.parse(e.target.result);
                if (parsed.boxes && parsed.workers && parsed.services) {
                    this.db = parsed;
                    this.saveDatabase();
                    this.renderAll();
                    alert('База данных успешно восстановлена!');
                } else {
                    alert('Неверный формат файла резервной копии.');
                }
            } catch (err) {
                alert('Ошибка чтения файла: ' + err.message);
            }
        };
        reader.readAsText(file);
    }
}

// Запуск приложения
const app = new CarWashApp();
