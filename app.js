/**
 * CarWash Tracker - Управление автомойкой (SPA)
 * Роли:
 * 1. Гость (Клиент) - проверка статуса своего авто по номеру, прайс-лист, контакты
 * 2. Мойщик - видит только свои назначенные машины, отмечает готовность, видит свой заработок (БЕЗ права добавления авто)
 * 3. Администратор - оформляет заезд авто, распределяет по боксам, принимает оплату
 * 4. Владелец - полный доступ: касса, чистая прибыль, зарплатный фонд, прайс, персонал
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
        this.currentRole = 'guest'; // 'guest', 'worker', 'admin', 'owner'
        this.currentWorkerId = null;
        this.activePaymentOrderId = null;
        
        this.loadDatabase();
        this.initDOM();
        this.applyRoleUI();
        this.renderAll();
    }

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
        const options = { day: 'numeric', month: 'long', year: 'numeric' };
        document.getElementById('shiftDate').textContent = new Date().toLocaleDateString('ru-RU', options);
    }

    // ==================== РОЛИ И ДОСТУП ====================

    applyRoleUI() {
        const badge = document.getElementById('currentRoleBadge');
        document.body.className = `role-${this.currentRole}`;

        if (this.currentRole === 'guest') {
            badge.textContent = '🚗 Режим: Клиент / Гость';
            badge.style.background = '#f1f5f9';
            badge.style.color = '#334155';
            this.switchTab('guestSearch');
        } else if (this.currentRole === 'worker') {
            const worker = this.db.workers.find(w => w.id === this.currentWorkerId);
            const workerName = worker ? worker.name : 'Сотрудник';
            badge.textContent = `🧽 Мойщик: ${workerName}`;
            badge.style.background = '#e0f2fe';
            badge.style.color = '#0369a1';
            this.switchTab('workerTasks');
        } else if (this.currentRole === 'admin') {
            badge.textContent = '📋 Кабинет: Администратор смены';
            badge.style.background = '#eff6ff';
            badge.style.color = '#2563eb';
            this.switchTab('activeOrders');
        } else if (this.currentRole === 'owner') {
            badge.textContent = '👑 Кабинет: Владелец (Директор)';
            badge.style.background = '#fef3c7';
            badge.style.color = '#b45309';
            this.switchTab('activeOrders');
        }
    }

    openAuthModal() {
        document.getElementById('authModal').classList.add('open');
        this.hideOwnerLoginForm();
        this.hideWorkerSelector();
    }

    closeAuthModal() {
        document.getElementById('authModal').classList.remove('open');
    }

    loginAsGuest() {
        this.currentRole = 'guest';
        this.currentWorkerId = null;
        this.applyRoleUI();
        this.closeAuthModal();
        this.renderAll();
    }

    showWorkerSelector() {
        const select = document.getElementById('workerModalSelect');
        select.innerHTML = '';
        this.db.workers.forEach(w => {
            const opt = document.createElement('option');
            opt.value = w.id;
            opt.textContent = `${w.name} (${w.percent}% от мойки)`;
            select.appendChild(opt);
        });

        document.getElementById('workerSelectBlock').style.display = 'block';
        document.getElementById('ownerPasswordBlock').style.display = 'none';
    }

    hideWorkerSelector() {
        document.getElementById('workerSelectBlock').style.display = 'none';
    }

    confirmWorkerLogin() {
        const selectedId = document.getElementById('workerModalSelect').value;
        if (!selectedId) {
            alert('Пожалуйста, выберите сотрудника!');
            return;
        }
        this.currentRole = 'worker';
        this.currentWorkerId = selectedId;
        this.applyRoleUI();
        this.closeAuthModal();
        this.renderAll();
    }

    loginAsAdmin() {
        this.currentRole = 'admin';
        this.currentWorkerId = null;
        this.applyRoleUI();
        this.closeAuthModal();
        this.renderAll();
    }

    showOwnerLoginForm() {
        document.getElementById('ownerPasswordBlock').style.display = 'block';
        document.getElementById('workerSelectBlock').style.display = 'none';
        document.getElementById('ownerPasswordInput').focus();
    }

    hideOwnerLoginForm() {
        document.getElementById('ownerPasswordBlock').style.display = 'none';
        document.getElementById('ownerPasswordInput').value = '';
    }

    submitOwnerLogin() {
        const inputPass = document.getElementById('ownerPasswordInput').value;
        if (inputPass === this.db.ownerPassword || inputPass === '9999') {
            this.currentRole = 'owner';
            this.currentWorkerId = null;
            this.applyRoleUI();
            this.closeAuthModal();
            this.renderAll();
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

    // ==================== НАВИГАЦИЯ ПО ВКЛАДКАМ ====================

    switchTab(tabId) {
        // Проверка прав
        if (['finance', 'settings'].includes(tabId) && this.currentRole !== 'owner') {
            this.openAuthModal();
            this.showOwnerLoginForm();
            return;
        }

        if (['newOrder', 'activeOrders', 'history'].includes(tabId) && !['admin', 'owner'].includes(this.currentRole)) {
            alert('Этот раздел доступен только Администратору или Владельцу.');
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
        if (tabId === 'workerTasks') this.renderWorkerTasks();
        if (tabId === 'workerHistory') this.renderWorkerHistory();
        if (tabId === 'guestSearch') this.renderGuestBoxesOverview();
        if (tabId === 'guestPrices') this.renderGuestPrices();
    }

    renderAll() {
        this.renderBoxesAndSelects();
        this.renderServicesCheckboxes();
        this.renderActiveOrders();
        this.renderHistory();
        this.renderFinance();
        this.renderSettings();
        this.renderWorkerTasks();
        this.renderWorkerHistory();
        this.renderGuestBoxesOverview();
        this.renderGuestPrices();
    }

    // ==================== ЛОГИКА ГОСТЯ (КЛИЕНТА) ====================

    searchCarStatus(event) {
        event.preventDefault();
        const input = document.getElementById('guestSearchPlate').value.trim().toUpperCase().replace(/\s+/g, '');
        const resultContainer = document.getElementById('guestSearchResult');

        if (!input) return;

        // Поиск машины в активных заказах
        const order = this.db.orders.find(o => o.carPlate.toUpperCase().replace(/\s+/g, '') === input);

        resultContainer.style.display = 'block';

        if (!order) {
            resultContainer.innerHTML = `
                <div style="color: #64748b; text-align: center; padding: 1rem;">
                    <h3>Автомобиль не найден</h3>
                    <p>Авто с госномером <strong>${document.getElementById('guestSearchPlate').value.toUpperCase()}</strong> сейчас нет в очереди.</p>
                    <small>Если вы только что заехали, администратор оформит заезд через минуту.</small>
                </div>
            `;
            return;
        }

        const box = this.db.boxes.find(b => b.id === order.boxId);
        const serviceNames = order.services.map(sid => {
            const s = this.db.services.find(item => item.id === sid);
            return s ? s.name : '';
        }).filter(Boolean).join(', ');

        if (order.status === 'in-progress') {
            resultContainer.innerHTML = `
                <div class="guest-plate-badge">${order.carPlate}</div>
                <div><strong>${order.carModel || 'Автомобиль'}</strong></div>
                <div class="guest-status-banner in-progress">
                    <span>🚿 Автомобиль моется в <strong>${box ? box.name : 'боксе'}</strong></span>
                </div>
                <p><strong>Выполняемые услуги:</strong> ${serviceNames}</p>
                <p><strong>Стоимость:</strong> ${order.totalPrice.toLocaleString()} ₸</p>
                <small class="text-muted">Пожалуйста, ожидайте в комнате отдыха. Мы сообщим о готовности!</small>
            `;
        } else if (order.status === 'ready') {
            resultContainer.innerHTML = `
                <div class="guest-plate-badge">${order.carPlate}</div>
                <div><strong>${order.carModel || 'Автомобиль'}</strong></div>
                <div class="guest-status-banner ready">
                    <span>✅ Автомобиль готов к выдаче! (${box ? box.name : 'Бокс'})</span>
                </div>
                <p><strong>Услуги:</strong> ${serviceNames}</p>
                <p><strong>К оплате:</strong> <strong style="color:var(--primary); font-size:1.2rem;">${order.totalPrice.toLocaleString()} ₸</strong></p>
                <small>Вы можете подойти к администратору для расчета и забрать авто.</small>
            `;
        } else if (order.status === 'paid') {
            resultContainer.innerHTML = `
                <div class="guest-plate-badge">${order.carPlate}</div>
                <div style="color: #10b981; font-weight: 600; padding: 0.5rem 0;">
                    ✅ Мойка завершена и оплачена. Спасибо, что выбрали нас!
                </div>
            `;
        }
    }

    renderGuestBoxesOverview() {
        const container = document.getElementById('guestBoxesOverview');
        if (!container) return;
        container.innerHTML = '';

        this.db.boxes.forEach(box => {
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
                    <div style="font-size:0.9rem; color:var(--text-muted); margin: 0.5rem 0;">
                        ${activeOrder.status === 'in-progress' ? '🚿 Идет мойка авто' : '✅ Готово к выдаче'}
                    </div>
                ` : `
                    <div style="color:var(--success); font-weight:500; margin: 0.5rem 0;">Готов к приему авто</div>
                `}
            `;
            container.appendChild(card);
        });
    }

    renderGuestPrices() {
        const tbody = document.getElementById('guestPriceTableBody');
        const category = document.getElementById('guestPriceCategory').value;
        const multiplier = CATEGORY_MULTIPLIERS[category] || 1.0;

        tbody.innerHTML = '';
        this.db.services.forEach(s => {
            const price = Math.round(s.basePrice * multiplier);
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${s.name}</strong></td>
                <td><strong style="color:var(--primary);">${price.toLocaleString()} ₸</strong></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ==================== ЛОГИКА МОЙЩИКА (РАБОЧЕГО) ====================

    renderWorkerTasks() {
        const worker = this.db.workers.find(w => w.id === this.currentWorkerId);
        document.getElementById('workerActiveName').textContent = worker ? worker.name : 'Не выбран';

        const cardsContainer = document.getElementById('workerAssignedCards');
        cardsContainer.innerHTML = '';

        if (!this.currentWorkerId) {
            cardsContainer.innerHTML = '<p class="text-muted">Сотрудник не выбран. Нажмите «Сменить режим» и выберите себя.</p>';
            return;
        }

        // Задачи в работе и готовые для этого мойщика
        const myTasks = this.db.orders.filter(o => o.workerId === this.currentWorkerId && (o.status === 'in-progress' || o.status === 'ready'));

        if (myTasks.length === 0) {
            cardsContainer.innerHTML = `
                <div class="card" style="grid-column: 1 / -1; text-align: center; color: #94a3b8; padding: 2.5rem;">
                    <h3>Нет назначенных машин</h3>
                    <p>Сейчас у вас нет активных автомобилей в боксах. Ожидайте назначения от администратора.</p>
                </div>
            `;
        } else {
            myTasks.forEach(order => {
                const box = this.db.boxes.find(b => b.id === order.boxId);
                const serviceNames = order.services.map(sid => {
                    const s = this.db.services.find(item => item.id === sid);
                    return s ? s.name : '';
                }).filter(Boolean).join(', ');

                const earnedForOrder = Math.round(order.totalPrice * (worker.percent / 100));

                const card = document.createElement('div');
                card.className = `worker-task-card ${order.status}`;
                card.innerHTML = `
                    <div>
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                            <span class="badge" style="background:#0f172a; color:#fff; font-size:0.9rem;">${box ? box.name : 'Бокс'}</span>
                            <span class="status-pill ${order.status}">
                                ${order.status === 'in-progress' ? '🚿 В процессе' : '✅ Готово'}
                            </span>
                        </div>
                        <h3 style="font-size:1.3rem; margin:0.3rem 0;">${order.carPlate}</h3>
                        <div class="text-muted">${order.carModel || 'Автомобиль'}</div>
                        <div style="margin: 0.75rem 0; font-size: 0.9rem;">
                            <strong>Услуги:</strong> ${serviceNames}
                        </div>
                        <div style="font-size:0.85rem; color:#0369a1; background:#e0f2fe; padding:0.4rem 0.6rem; border-radius:6px;">
                            Ваша выплата за этот авто: <strong>${earnedForOrder.toLocaleString()} ₸</strong> (${worker.percent}%)
                        </div>
                    </div>
                    <div style="margin-top: 1.25rem;">
                        ${order.status === 'in-progress' ? `
                            <button class="btn btn-success" style="width:100%;" onclick="app.setOrderReady(${order.id})">
                                ✅ Завершил мойку (Готово)
                            </button>
                        ` : `
                            <div style="text-align:center; color:#15803d; font-weight:600; font-size:0.9rem;">
                                Ожидает оплаты у администратора
                            </div>
                        `}
                    </div>
                `;
                cardsContainer.appendChild(card);
            });
        }

        // Обновление статистики мойщика за сегодня
        this.updateWorkerStats();
    }

    updateWorkerStats() {
        if (!this.currentWorkerId) return;

        const worker = this.db.workers.find(w => w.id === this.currentWorkerId);
        if (!worker) return;

        const todayStr = new Date().toISOString().split('T')[0];

        let count = 0;
        let earned = 0;

        this.db.orders.forEach(o => {
            if (o.workerId === this.currentWorkerId && o.status === 'paid') {
                const dateStr = new Date(o.paidAt || o.createdAt).toISOString().split('T')[0];
                if (dateStr === todayStr) {
                    count++;
                    earned += Math.round(o.totalPrice * (worker.percent / 100));
                }
            }
        });

        document.getElementById('workerStatsCount').textContent = `${count} авто`;
        document.getElementById('workerStatsEarned').textContent = `${earned.toLocaleString()} ₸`;
    }

    renderWorkerHistory() {
        const tbody = document.getElementById('workerHistoryTableBody');
        tbody.innerHTML = '';

        if (!this.currentWorkerId) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:2rem;">Сотрудник не выбран.</td></tr>`;
            return;
        }

        const worker = this.db.workers.find(w => w.id === this.currentWorkerId);
        const myHistory = this.db.orders.filter(o => o.workerId === this.currentWorkerId && o.status === 'paid');

        if (myHistory.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:2rem;">У вас пока нет закрытых заказов за смену.</td></tr>`;
            return;
        }

        myHistory.forEach(order => {
            const timeStr = new Date(order.paidAt || order.createdAt).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            const serviceNames = order.services.map(sid => {
                const s = this.db.services.find(item => item.id === sid);
                return s ? s.name : '';
            }).filter(Boolean).join(', ');

            const earned = Math.round(order.totalPrice * (worker.percent / 100));

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${timeStr}</td>
                <td><strong>${order.carPlate}</strong></td>
                <td>${order.carModel || '—'}</td>
                <td style="font-size:0.85rem; max-width:200px;">${serviceNames}</td>
                <td>${order.totalPrice.toLocaleString()} ₸</td>
                <td><strong style="color:var(--primary);">${earned.toLocaleString()} ₸</strong></td>
                <td><span class="status-pill ready">Выполнено</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ==================== ЛОГИКА АДМИНИСТРАТОРА И ВЛАДЕЛЬЦА ====================

    renderBoxesAndSelects() {
        const container = document.getElementById('boxesContainer');
        const boxSelect = document.getElementById('orderBox');
        container.innerHTML = '';
        boxSelect.innerHTML = '';

        this.db.boxes.forEach(box => {
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
                    <div class="text-muted" style="margin: 1rem 0;">Бокс свободен</div>
                    <button class="btn btn-outline btn-sm" onclick="app.quickAssignBox(${box.id})">+ Запустить авто</button>
                `}
            `;
            container.appendChild(card);

            const option = document.createElement('option');
            option.value = box.id;
            option.textContent = `${box.name} ${isBusy ? '(Занят)' : '(Свободен)'}`;
            boxSelect.appendChild(option);
        });

        // Селект мойщиков для формы
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
        if (!['admin', 'owner'].includes(this.currentRole)) {
            alert('Оформлять заезд может только Администратор или Владелец.');
            return;
        }
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

        // Строгая защита: мойщик не может создать заказ
        if (!['admin', 'owner'].includes(this.currentRole)) {
            alert('У мойщиков нет доступа к добавлению машин. Это делает администратор.');
            return;
        }

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
        if (!['admin', 'owner'].includes(this.currentRole)) {
            alert('Принимать оплату может только Администратор или Владелец.');
            return;
        }

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

    // ==================== КАССА И АНАЛИТИКА (ВЛАДЕЛЕЦ) ====================

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

            if (dateStr === todayStr) {
                todayIncome += o.totalPrice;
                todayCount += 1;
            }

            if (orderDate.getMonth() === currentMonth && orderDate.getFullYear() === currentYear) {
                monthIncome += o.totalPrice;
                monthCount += 1;
            }

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
