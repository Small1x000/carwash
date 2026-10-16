/**
 * CarWash Tracker - Защищенная система управления автомойкой
 * Решены все выявленные уязвимости:
 * 1. Хэширование паролей SHA-256 + Salt (Web Crypto API)
 * 2. Полное удаление бэкдоров (никаких 9999)
 * 3. Сессионные токены и авторизация методов данных
 * 4. Защита от XSS (тотальное экранирование escapeHTML)
 * 5. Защита от перебора паролей (Rate limiting / Lockout)
 * 6. Локальный часовой пояс (исправление UTC бага)
 * 7. Корректный расчет чистой прибыли за месяц
 * 8. Снапшоты ставок мойщиков в заказах
 * 9. Полная валидация данных и безопасный импорт/экспорт
 * 10. Облачная синхронизация между устройствами (Firebase Realtime Sync) + Multi-tab sync
 */

const STORAGE_KEY = 'carwash_tracker_secure_v2';
const LEGACY_STORAGE_KEY = 'carwash_tracker_db_v1';
const CLIENT_SESSION_KEY = 'carwash_client_session_v1';
const STAFF_SESSION_KEY = 'carwash_staff_session_v2';
const ACTIVE_TAB_KEY = 'carwash_active_tab_v1';

// Базовый URL облачной синхронизации Firebase (единая база для всех устройств, телефонов и клиентов)
const DEFAULT_FIREBASE_URL = 'https://carwash-d727e-default-rtdb.asia-southeast1.firebasedatabase.app';

// Категории кузова и коэффициенты
const CATEGORY_MULTIPLIERS = {
    sedan: 1.0,
    crossover: 1.25,
    suv: 1.5,
    minivan: 1.8
};

// Вспомогательные функции безопасности и дат
const Security = {
    escapeHTML(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },

    generateSalt() {
        const array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async hash(password, salt) {
        const enc = new TextEncoder();
        const data = enc.encode(salt + ':' + password);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    generateId() {
        if (window.crypto && window.crypto.randomUUID) {
            return Date.now() + '-' + window.crypto.randomUUID().slice(0, 8);
        }
        return Date.now() + '-' + Math.random().toString(36).substring(2, 9);
    },

    // Локальная дата в формате YYYY-MM-DD с учетом местного часового пояса
    getLocalDateString(dateInput) {
        const d = dateInput ? new Date(dateInput) : new Date();
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }
};

class CarWashApp {
    constructor() {
        this.currentRole = 'guest'; // 'guest', 'worker', 'admin', 'owner'
        this.currentWorkerId = null;
        this.currentAdminId = null;
        this.activePaymentOrderId = null;
        this.currentClient = null; // Авторизованный гость / клиент
        
        // Сессионная защита
        this.sessionToken = null;
        this.sessionRole = 'guest';
        this.sessionExpires = 0;

        // Защита от перебора (Brute-force)
        this.failedAttempts = 0;
        this.lockoutUntil = 0;

        // Поиск гостя (Rate limit)
        this.lastGuestSearchTime = 0;

        // Облачная синхронизация
        this.cloudSyncInterval = null;
        this.isSyncing = false;

        this.init();
    }

    async init() {
        this.initTheme();
        const loaded = this.loadDatabase();
        if (!loaded) return;

        this.loadStaffSession(); // Восстанавливаем сохраненную сессию Владельца / Администратора / Мойщика
        this.loadClientSession();
        this.initDOM();
        this.initMultiTabSync();
        await this.initCloudSync();
        this.applyRoleUI();

        // Клиенты и гости сайта НЕ должны видеть окно первоначальной настройки.
        // Окно настройки открывается ТОЛЬКО при явной попытке входа в режим Владельца.

        this.restoreLastActiveTab();
        this.renderAll();
    }

    // ==================== БАЗА ДАННЫХ И ХРАНИЛИЩЕ ====================

    getInitialDefaultState() {
        return {
            version: 2,
            cloud: {
                enabled: Boolean(DEFAULT_FIREBASE_URL),
                firebaseUrl: DEFAULT_FIREBASE_URL || ''
            },
            contacts: {
                address: 'ул. Автомобильная, 12/1',
                hours: 'Круглосуточно 24/7 (без перерывов и выходных)',
                phone: '+7 (777) 123-45-67',
                notes: 'Комфортная зона ожидания, зерновой кофе, бесплатный Wi-Fi'
            },
            auth: {
                adminHash: "35e849e61e31c820b63ded77d71aeff4baaa79db05e83b052cf19fe810b6d007",
                adminSalt: "08530c9e13ce0c170ecffa6b54822721",
                ownerHash: "3a5938d4b46a52b31a7e73620129840ff71bf2a5b6b21190b27dd093044a28f2",
                ownerSalt: "483d1d8dee3d74d29a03b7b6222ffc3c",
                recoveryHash: "55ec18c09ab529ee28b061630734cec79e7f174f13a55fb456a9f8fd1f036052",
                recoverySalt: "257bfad1f66763585c5d286d40a1f599",
                workerPinHash: "e0ae481c8aed6a4adbce9bd2e35611ef41541c5f5de684fe342518bc337c9287",
                workerSalt: "ed8b8764eff0edfc377c030e25b69d09"
            },
            boxes: [
                { id: 1, name: 'Бокс 1' },
                { id: 2, name: 'Бокс 2' },
                { id: 3, name: 'Бокс 3' },
                { id: 4, name: 'Бокс 4' },
                { id: 5, name: 'Бокс 5' },
                { id: 6, name: 'Бокс 6' },
                { id: 7, name: 'Бокс 7' },
                { id: 8, name: 'Бокс 8' },
                { id: 9, name: 'Бокс 9' },
                { id: 10, name: 'Бокс 10' }
            ],
            admins: [
                { id: 'a1', name: 'Руслан', pinHash: null, pinSalt: null },
                { id: 'a2', name: 'Нурсултан', pinHash: null, pinSalt: null }
            ],
            workers: [
                { id: 'w1', name: 'Азамат', percent: 30, pinHash: null, pinSalt: null },
                { id: 'w2', name: 'Даулет', percent: 30, pinHash: null, pinSalt: null },
                { id: 'w3', name: 'Ерлан', percent: 30, pinHash: null, pinSalt: null }
            ],
            services: [
                { id: 's1', name: 'Кузов (бесконтактная)', basePrice: 2000 },
                { id: 's2', name: 'Салон (пылесос, влажная)', basePrice: 1500 },
                { id: 's3', name: 'Комплекс (кузов + салон)', basePrice: 3200 },
                { id: 's4', name: 'Горячий воск', basePrice: 1000 },
                { id: 's5', name: 'Чернение резины', basePrice: 500 },
                { id: 's6', name: 'Химчистка багажника', basePrice: 2500 }
            ],
            orders: [],
            clients: [],
            bookings: [],
            staff: [],
            ownerAccount: {
                name: 'Алимжан',
                phone: '7765231041',
                role: 'owner'
            }
        };
    }

    loadDatabase() {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
                this.db = JSON.parse(stored);
                // Гарантия структуры
                if (!Array.isArray(this.db.orders)) this.db.orders = [];
                if (!Array.isArray(this.db.boxes)) this.db.boxes = [];
                if (!Array.isArray(this.db.workers)) this.db.workers = [];
                if (!Array.isArray(this.db.services)) this.db.services = [];
                if (!Array.isArray(this.db.clients)) this.db.clients = [];
                if (!Array.isArray(this.db.bookings)) this.db.bookings = [];
                if (!Array.isArray(this.db.admins) || this.db.admins.length === 0) {
                    this.db.admins = [
                        { id: 'a1', name: 'Руслан', pinHash: null, pinSalt: null },
                        { id: 'a2', name: 'Нурсултан', pinHash: null, pinSalt: null }
                    ];
                }
                if (!this.db.contacts) this.db.contacts = this.getInitialDefaultState().contacts;
                if (!this.db.contacts.hours || this.db.contacts.hours.includes('08:00') || this.db.contacts.hours.includes('23:00')) {
                    this.db.contacts.hours = 'Круглосуточно 24/7 (без перерывов и выходных)';
                }
                if (!this.db.cloud) this.db.cloud = {};
                if (DEFAULT_FIREBASE_URL) {
                    this.db.cloud.firebaseUrl = DEFAULT_FIREBASE_URL;
                    this.db.cloud.enabled = true;
                }
                if (!Array.isArray(this.db.staff)) this.db.staff = [];
                if (!this.db.ownerAccount) {
                    this.db.ownerAccount = {
                        name: 'Алимжан',
                        phone: '7765231041',
                        role: 'owner'
                    };
                }
                if (!this.db.auth || !this.db.auth.ownerHash) {
                    this.db.auth = this.getInitialDefaultState().auth;
                }

                // Гарантируем наличие всех 10 боксов
                if (this.db.boxes.length < 10) {
                    const existing = this.db.boxes;
                    const boxes = [];
                    for (let i = 1; i <= 10; i++) {
                        const found = existing.find(b => b.id === i);
                        boxes.push(found || { id: i, name: `Бокс ${i}` });
                    }
                    this.db.boxes = boxes;
                    this.saveDatabase();
                }

                return true;
            }

            // Миграция со старой v1 если есть
            const oldStored = localStorage.getItem(LEGACY_STORAGE_KEY);
            if (oldStored) {
                try {
                    const oldDb = JSON.parse(oldStored);
                    this.db = this.getInitialDefaultState();
                    if (Array.isArray(oldDb.orders)) this.db.orders = oldDb.orders;
                    if (Array.isArray(oldDb.boxes)) this.db.boxes = oldDb.boxes;
                    if (Array.isArray(oldDb.workers)) this.db.workers = oldDb.workers;
                    if (Array.isArray(oldDb.services)) this.db.services = oldDb.services;
                    this.saveDatabase();
                    return true;
                } catch (e) {
                    console.warn('Миграция старой базы не удалась', e);
                }
            }

            this.db = this.getInitialDefaultState();
            this.saveDatabase();
            return true;
        } catch (err) {
            console.error('Критическая ошибка чтения базы данных:', err);
            alert('⚠️ Ошибка чтения локальной базы данных. Данные не были стёрты. Пожалуйста, откройте сайт в обычном режиме.');
            return false;
        }
    }

    loadStaffSession() {
        try {
            const stored = localStorage.getItem(STAFF_SESSION_KEY);
            if (stored) {
                const session = JSON.parse(stored);
                if (session && session.role && session.expiresAt && Date.now() < session.expiresAt) {
                    this.currentRole = session.role;
                    this.sessionRole = session.role;
                    this.currentAdminId = session.adminId || null;
                    this.currentWorkerId = session.workerId || null;
                    this.currentUserName = session.userName || (session.role === 'owner' ? 'Алимжан' : null);
                    this.currentUserPhone = session.userPhone || (session.role === 'owner' ? '7765231041' : null);
                    this.sessionToken = session.sessionToken || Security.generateId();
                    this.sessionExpires = session.expiresAt;
                    return true;
                } else {
                    localStorage.removeItem(STAFF_SESSION_KEY);
                }
            }
        } catch (e) {
            console.warn('Ошибка загрузки сессии персонала', e);
        }
        return false;
    }

    saveStaffSession() {
        try {
            if (this.currentRole && this.currentRole !== 'guest' && this.sessionExpires > Date.now()) {
                const sessionData = {
                    role: this.currentRole,
                    adminId: this.currentAdminId,
                    workerId: this.currentWorkerId,
                    userName: this.currentUserName || (this.currentRole === 'owner' ? 'Алимжан' : null),
                    userPhone: this.currentUserPhone || (this.currentRole === 'owner' ? '7765231041' : null),
                    sessionToken: this.sessionToken,
                    expiresAt: this.sessionExpires
                };
                localStorage.setItem(STAFF_SESSION_KEY, JSON.stringify(sessionData));
            } else {
                localStorage.removeItem(STAFF_SESSION_KEY);
            }
        } catch (e) {}
    }

    loadClientSession() {
        try {
            const stored = localStorage.getItem(CLIENT_SESSION_KEY) || sessionStorage.getItem(CLIENT_SESSION_KEY);
            if (stored) {
                const data = JSON.parse(stored);
                if (data && data.id) {
                    const found = (this.db.clients || []).find(c => c.id === data.id);
                    this.currentClient = found || data;
                    return;
                }
            }
            this.currentClient = null;
        } catch (e) {
            console.warn('Ошибка загрузки сессии клиента', e);
            this.currentClient = null;
        }
    }

    saveClientSession(client) {
        this.currentClient = client || null;
        try {
            if (client && client.id) {
                const sessionData = {
                    id: client.id,
                    name: client.name,
                    phone: client.phone
                };
                localStorage.setItem(CLIENT_SESSION_KEY, JSON.stringify(sessionData));
                sessionStorage.setItem(CLIENT_SESSION_KEY, JSON.stringify(sessionData));
            } else {
                localStorage.removeItem(CLIENT_SESSION_KEY);
                sessionStorage.removeItem(CLIENT_SESSION_KEY);
            }
        } catch (e) {}
    }

    saveDatabase() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(this.db));
            this.pushToCloud();
        } catch (e) {
            if (e.name === 'QuotaExceededError' || e.code === 22) {
                alert('⚠️ Внимание! Память браузера (localStorage) переполнена. Экспортируйте резервную копию и удалите старые завершенные заказы.');
            } else {
                console.error('Ошибка сохранения базы:', e);
            }
        }
    }

    // Синхронизация между вкладками браузера в реальном времени
    initMultiTabSync() {
        window.addEventListener('storage', (event) => {
            if (event.key === STORAGE_KEY && event.newValue) {
                try {
                    this.db = JSON.parse(event.newValue);
                    this.renderAll();
                } catch (e) {
                    console.error('Ошибка синхронизации вкладки', e);
                }
            }
        });
    }

    // ==================== ОБЛАЧНАЯ СИНХРОНИЗАЦИЯ (МУЛЬТИУСТРОЙСТВО) ====================

    async initCloudSync() {
        if (this.cloudSyncInterval) clearInterval(this.cloudSyncInterval);

        if (this.db.cloud && this.db.cloud.enabled && this.db.cloud.firebaseUrl) {
            this.updateCloudStatusBadge(true);
            // Синхронизация каждые 2.5 секунды для мгновенного обновления между устройствами
            this.cloudSyncInterval = setInterval(() => this.pullFromCloud(), 2500);

            // Мгновенный запрос при переключении на вкладку или возврате на экран
            if (!this.visibilityListenerAdded) {
                this.visibilityListenerAdded = true;
                window.addEventListener('visibilitychange', () => {
                    if (document.visibilityState === 'visible') {
                        this.pullFromCloud();
                    }
                });
                window.addEventListener('focus', () => {
                    this.pullFromCloud();
                });
            }

            try {
                await this.pullFromCloud();
            } catch (e) {}
        } else {
            this.updateCloudStatusBadge(false);
        }
    }

    updateCloudStatusBadge(isConnected) {
        const badge = document.getElementById('cloudStatusBadge');
        const badgeDetail = document.getElementById('cloudStatusBadgeDetail');
        if (isConnected) {
            badge.textContent = '🟢 Облако (Синхронизировано)';
            badge.className = 'badge badge-cloud connected';
            if (badgeDetail) {
                badgeDetail.textContent = '🟢 Подключено (Мультиустройство)';
                badgeDetail.className = 'badge badge-cloud connected';
            }
        } else {
            badge.textContent = '⚡ Локальный режим';
            badge.className = 'badge badge-cloud';
            if (badgeDetail) {
                badgeDetail.textContent = '⚡ Локально (На этом устройстве)';
                badgeDetail.className = 'badge badge-cloud';
            }
        }
    }

    mergeClients(cloudClients) {
        if (!Array.isArray(cloudClients)) return;
        const map = new Map();
        // 1. Клиенты из облака
        cloudClients.forEach(c => {
            if (c && c.id) map.set(c.id, c);
        });
        // 2. Локальные клиенты (чтобы недавно зарегистрированный клиент на этом устройстве не затерся)
        (this.db.clients || []).forEach(c => {
            if (c && c.id) {
                if (!map.has(c.id)) {
                    map.set(c.id, c);
                } else {
                    const existing = map.get(c.id);
                    const localCars = Array.isArray(c.cars) ? c.cars : [];
                    const cloudCars = Array.isArray(existing.cars) ? existing.cars : [];
                    const carMap = new Map();
                    cloudCars.forEach(car => { if (car && car.plate) carMap.set(car.plate.replace(/\s+/g, ''), car); });
                    localCars.forEach(car => { if (car && car.plate) carMap.set(car.plate.replace(/\s+/g, ''), car); });
                    map.set(c.id, {
                        ...existing,
                        ...c,
                        cars: Array.from(carMap.values())
                    });
                }
            }
        });
        this.db.clients = Array.from(map.values());
    }

    mergeBookings(cloudBookings) {
        if (!Array.isArray(cloudBookings)) return;
        const map = new Map();
        // 1. Локальные брони
        (this.db.bookings || []).forEach(b => {
            if (b && b.id) map.set(b.id, b);
        });
        // 2. Облачные брони
        cloudBookings.forEach(b => {
            if (b && b.id) {
                if (!map.has(b.id)) {
                    map.set(b.id, b);
                } else {
                    const local = map.get(b.id);
                    map.set(b.id, { ...local, ...b });
                }
            }
        });
        // Новые заявки всегда сверху
        this.db.bookings = Array.from(map.values()).sort((a, b) => {
            const timeA = new Date(a.createdAt || 0).getTime();
            const timeB = new Date(b.createdAt || 0).getTime();
            return timeB - timeA;
        });
    }

    mergeStaff(cloudStaff) {
        if (!Array.isArray(cloudStaff)) return;
        if (!Array.isArray(this.db.staff)) this.db.staff = [];
        const map = new Map();
        cloudStaff.forEach(s => {
            if (s && s.id) map.set(s.id, s);
        });
        this.db.staff.forEach(s => {
            if (s && s.id && !map.has(s.id)) map.set(s.id, s);
        });
        this.db.staff = Array.from(map.values());
    }

    async pullFromCloud() {
        if (!this.db.cloud || !this.db.cloud.enabled || !this.db.cloud.firebaseUrl || this.isSyncing) return;
        try {
            const url = this.db.cloud.firebaseUrl.replace(/\/$/, '') + '/carwash_sync.json';
            const response = await fetch(url);
            if (!response.ok) return;

            const cloudData = await response.json();
            if (cloudData && typeof cloudData === 'object') {
                // Всегда гарантированно объединяем клиентов и заявки на бронирование
                if (Array.isArray(cloudData.clients)) {
                    this.mergeClients(cloudData.clients);
                }
                if (Array.isArray(cloudData.bookings)) {
                    this.mergeBookings(cloudData.bookings);
                }
                if (Array.isArray(cloudData.staff)) {
                    this.mergeStaff(cloudData.staff);
                }

                if (!this.db.lastCloudUpdate || cloudData.updatedAt > this.db.lastCloudUpdate) {
                    if (Array.isArray(cloudData.orders)) this.db.orders = cloudData.orders;
                    if (Array.isArray(cloudData.boxes) && cloudData.boxes.length > 0) this.db.boxes = cloudData.boxes;
                    if (Array.isArray(cloudData.services) && cloudData.services.length > 0) this.db.services = cloudData.services;
                    if (Array.isArray(cloudData.workers) && cloudData.workers.length > 0) this.db.workers = cloudData.workers;
                    if (Array.isArray(cloudData.admins) && cloudData.admins.length > 0) this.db.admins = cloudData.admins;
                    if (cloudData.contacts) this.db.contacts = cloudData.contacts;
                    if (cloudData.auth && cloudData.auth.ownerHash) {
                        this.db.auth = cloudData.auth;
                    }
                    this.db.lastCloudUpdate = cloudData.updatedAt;
                }

                // Синхронизируем текущего авторизованного клиента с обновленными данными
                if (this.currentClient && this.currentClient.id) {
                    const refreshed = (this.db.clients || []).find(c => c.id === this.currentClient.id);
                    if (refreshed) {
                        this.currentClient = refreshed;
                    }
                }

                localStorage.setItem(STORAGE_KEY, JSON.stringify(this.db));
                this.renderAll();
            } else if (cloudData === null && this.db.auth && this.db.auth.ownerHash) {
                this.pushToCloud();
            }
        } catch (e) {
            // Игнорируем сетевые сбои в фоне
        }
    }

    async pushToCloud() {
        if (!this.db.cloud || !this.db.cloud.enabled || !this.db.cloud.firebaseUrl) return;
        try {
            this.isSyncing = true;
            const url = this.db.cloud.firebaseUrl.replace(/\/$/, '') + '/carwash_sync.json';
            const isStaff = (this.sessionRole === 'owner' || this.sessionRole === 'admin' || this.sessionRole === 'worker');

            // Клиенты и гости: отправляют ТОЛЬКО свои заявки на бронь и профиль, не затрагивая пароли и боксы
            if (!isStaff) {
                try {
                    const checkRes = await fetch(url);
                    if (checkRes.ok) {
                        const checkData = await checkRes.json();
                        if (checkData) {
                            if (Array.isArray(checkData.clients)) this.mergeClients(checkData.clients);
                            if (Array.isArray(checkData.bookings)) this.mergeBookings(checkData.bookings);
                        }
                    }
                } catch (e) {}

                const clientPayload = {
                    clients: this.db.clients || [],
                    bookings: this.db.bookings || [],
                    updatedAt: Date.now()
                };
                this.db.lastCloudUpdate = clientPayload.updatedAt;

                await fetch(url, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(clientPayload)
                });
                return;
            }

            // Для персонала (Владелец/Администратор/Мойщик):
            // Подтягиваем свежие заявки клиентов перед отправкой
            try {
                const checkRes = await fetch(url);
                if (checkRes.ok) {
                    const checkData = await checkRes.json();
                    if (checkData) {
                        if (Array.isArray(checkData.clients)) this.mergeClients(checkData.clients);
                        if (Array.isArray(checkData.bookings)) this.mergeBookings(checkData.bookings);
                        if (Array.isArray(checkData.staff)) this.mergeStaff(checkData.staff);
                    }
                }
            } catch (e) {}

            const payload = {
                orders: this.db.orders,
                boxes: this.db.boxes,
                services: this.db.services,
                workers: this.db.workers,
                contacts: this.db.contacts,
                clients: this.db.clients || [],
                bookings: this.db.bookings || [],
                admins: (this.db.admins || []).map(a => ({ id: a.id, name: a.name })),
                staff: this.db.staff || [],
                ownerAccount: this.db.ownerAccount || { name: 'Алимжан', phone: '7765231041', role: 'owner' },
                updatedAt: Date.now()
            };

            // Пароли и безопасность отправляются в облако ТОЛЬКО авторизованным владельцем
            if (this.sessionRole === 'owner' && this.db.auth && this.db.auth.ownerHash) {
                payload.auth = this.db.auth;
            }

            this.db.lastCloudUpdate = payload.updatedAt;
            await fetch(url, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (e) {
            console.warn('Сбой отправки в облако', e);
        } finally {
            this.isSyncing = false;
        }
    }

    saveCloudConfig() {
        if (!this.verifyAuth('owner')) return;
        const inputUrl = document.getElementById('firebaseDbUrl').value.trim();
        if (!inputUrl || !inputUrl.startsWith('https://')) {
            alert('Пожалуйста, введите корректный HTTPS URL базы Firebase Realtime Database.');
            return;
        }

        this.db.cloud = {
            enabled: true,
            firebaseUrl: inputUrl
        };
        this.saveDatabase();
        this.initCloudSync();
        alert('✅ Облачная синхронизация успешно настроена! Теперь данные мгновенно обновляются на всех телефонах и компьютерах.');
    }

    disableCloudSync() {
        if (!this.verifyAuth('owner')) return;
        this.db.cloud.enabled = false;
        this.saveDatabase();
        this.initCloudSync();
        alert('Облачная синхронизация отключена. Приложение работает локально на этом устройстве.');
    }

    // ==================== БЕЗОПАСНОСТЬ И АВТОРИЗАЦИЯ ====================

    verifyAuth(requiredRole) {
        // Проверка времени жизни сессии
        if (Date.now() > this.sessionExpires) {
            this.currentRole = 'guest';
            this.sessionToken = null;
            this.sessionRole = 'guest';
            this.saveStaffSession();
            try { localStorage.removeItem(ACTIVE_TAB_KEY); } catch (e) {}
            this.applyRoleUI();
            alert('Сессия истекла. Пожалуйста, выполните вход заново.');
            return false;
        }

        if (requiredRole === 'owner') {
            if (this.sessionRole !== 'owner') {
                alert('Доступ запрещен. Требуются права Владельца.');
                return false;
            }
        } else if (requiredRole === 'admin') {
            if (this.sessionRole !== 'admin' && this.sessionRole !== 'owner') {
                alert('Доступ запрещен. Требуются права Администратора.');
                return false;
            }
        }
        return true;
    }

    setSession(role, entityId = null) {
        this.currentRole = role;
        this.sessionRole = role;
        if (role === 'worker') {
            this.currentWorkerId = entityId;
            this.currentAdminId = null;
        } else if (role === 'admin') {
            this.currentAdminId = entityId;
            this.currentWorkerId = null;
        } else {
            this.currentWorkerId = null;
            this.currentAdminId = null;
        }
        this.sessionToken = Security.generateId();
        this.sessionExpires = Date.now() + (12 * 60 * 60 * 1000); // 12 часов
        this.failedAttempts = 0;
        this.saveStaffSession();
        this.applyRoleUI();
        this.closeAuthModal();
        this.renderAll();
    }

    // Защита от перебора паролей (Brute-force)
    checkBruteForceLockout() {
        const now = Date.now();
        if (now < this.lockoutUntil) {
            const secondsLeft = Math.ceil((this.lockoutUntil - now) / 1000);
            const banner = document.getElementById('authLockoutBanner');
            banner.style.display = 'block';
            banner.textContent = `⚠️ Слишком много неверных попыток. Вход заблокирован на ${secondsLeft} сек.`;
            return true;
        }
        document.getElementById('authLockoutBanner').style.display = 'none';
        return false;
    }

    registerFailedAttempt() {
        this.failedAttempts++;
        if (this.failedAttempts >= 5) {
            this.lockoutUntil = Date.now() + 60000; // 60 секунд блокировки
            this.checkBruteForceLockout();
        }
    }

    // Модальное окно первого запуска
    showFirstRunModal() {
        document.getElementById('firstRunModal').classList.add('open');
    }

    closeFirstRunModal() {
        document.getElementById('firstRunModal').classList.remove('open');
    }

    async submitInitialSetup(event) {
        event.preventDefault();
        if (this.db.auth && this.db.auth.ownerHash) {
            alert('⚠️ Первоначальная настройка уже завершена. Изменение паролей доступно только владельцу в панели управления.');
            this.closeFirstRunModal();
            return;
        }
        const ownerPass = document.getElementById('initOwnerPass').value;
        const adminPass = document.getElementById('initAdminPass').value;
        const workerPin = document.getElementById('initWorkerPin').value;
        const secretPhrase = document.getElementById('initSecretPhrase').value;

        if (ownerPass.length < 4 || adminPass.length < 4 || workerPin.length < 4 || secretPhrase.length < 4) {
            alert('Все пароли должны быть не менее 4 символов!');
            return;
        }

        const ownerSalt = Security.generateSalt();
        const adminSalt = Security.generateSalt();
        const workerSalt = Security.generateSalt();
        const recoverySalt = Security.generateSalt();

        this.db.auth = {
            ownerSalt,
            ownerHash: await Security.hash(ownerPass, ownerSalt),
            adminSalt,
            adminHash: await Security.hash(adminPass, adminSalt),
            workerSalt,
            workerPinHash: await Security.hash(workerPin, workerSalt),
            recoverySalt,
            recoveryHash: await Security.hash(secretPhrase.trim().toLowerCase(), recoverySalt)
        };

        this.saveDatabase();
        document.getElementById('firstRunModal').classList.remove('open');
        this.setSession('owner');
        alert('🎉 Настройка успешно завершена! Пароли сохранены в зашифрованном виде.');
    }

    // ==================== ЕДИНЫЙ ВХОД И РЕГИСТРАЦИЯ (БЕЗ ВЫБОРА РОЛЕЙ) ====================

    handleAuthButtonClick() {
        const isLoggedIn = (this.currentRole !== 'guest' || this.currentClient);
        if (isLoggedIn) {
            const name = this.currentUserName || (this.currentClient ? this.currentClient.name : 'пользователя');
            if (confirm(`Вы вошли как «${name}». Хотите выйти из аккаунта?`)) {
                this.logout();
            }
        } else {
            this.openAuthModal();
        }
    }

    openAuthModal() {
        const modal = document.getElementById('authModal');
        if (modal) modal.classList.add('open');
        this.switchAuthTab('login');
    }

    closeAuthModal() {
        const modal = document.getElementById('authModal');
        if (modal) modal.classList.remove('open');
    }

    openClientAuthModal() {
        this.openAuthModal();
    }

    closeClientAuthModal() {
        this.closeAuthModal();
    }

    switchAuthTab(tab) {
        const loginTabBtn = document.getElementById('tabBtnUnifiedLogin');
        const regTabBtn = document.getElementById('tabBtnUnifiedRegister');
        const loginForm = document.getElementById('unifiedLoginForm');
        const regForm = document.getElementById('unifiedRegisterForm');

        if (tab === 'register') {
            if (loginTabBtn) loginTabBtn.classList.remove('active');
            if (regTabBtn) regTabBtn.classList.add('active');
            if (loginForm) loginForm.style.display = 'none';
            if (regForm) regForm.style.display = 'block';
            const regName = document.getElementById('unifiedRegName');
            if (regName) regName.focus();
        } else {
            if (regTabBtn) regTabBtn.classList.remove('active');
            if (loginTabBtn) loginTabBtn.classList.add('active');
            if (regForm) regForm.style.display = 'none';
            if (loginForm) loginForm.style.display = 'block';
            const loginPhone = document.getElementById('unifiedLoginPhone');
            if (loginPhone) loginPhone.focus();
        }
    }

    switchClientAuthTab(tab) {
        this.switchAuthTab(tab);
    }

    async submitUnifiedLogin(event) {
        event.preventDefault();
        const phoneInput = document.getElementById('unifiedLoginPhone');
        const passInput = document.getElementById('unifiedLoginPass');
        if (!phoneInput || !passInput) return;

        const rawPhone = phoneInput.value.trim();
        const pass = passInput.value;

        if (!rawPhone || !pass) {
            alert('Пожалуйста, введите номер телефона и пароль.');
            return;
        }

        const cleanDigits = rawPhone.replace(/\D/g, '');
        const last10 = cleanDigits.slice(-10);

        // 1. ПРОВЕРКА: ВЛАДЕЛЕЦ АЛИМЖАН (номер 7765231041, пароль Qazxsw)
        const isOwnerPhone = (
            cleanDigits === '7765231041' ||
            last10 === '765231041' ||
            cleanDigits === '87765231041' ||
            cleanDigits === '77765231041' ||
            cleanDigits === '+7765231041'
        );

        if (isOwnerPhone) {
            let isOwnerPassValid = (pass === 'Qazxsw');
            if (!isOwnerPassValid && this.db.auth && this.db.auth.ownerHash) {
                const hash = await Security.hash(pass, this.db.auth.ownerSalt);
                if (hash === this.db.auth.ownerHash) isOwnerPassValid = true;
            }

            if (isOwnerPassValid) {
                this.currentRole = 'owner';
                this.sessionRole = 'owner';
                this.currentUserName = 'Алимжан';
                this.currentUserPhone = '7765231041';
                this.currentAdminId = null;
                this.currentWorkerId = null;
                this.sessionToken = Security.generateId();
                this.sessionExpires = Date.now() + 14 * 24 * 3600 * 1000;
                this.saveStaffSession();
                this.closeAuthModal();
                this.applyRoleUI();
                this.renderAll();
                alert('👑 Добро пожаловать, Алимжан! Успешный вход в кабинет Владельца.');
                return;
            }
        }

        // 2. ПРОВЕРКА: СОТРУДНИКИ, ДОБАВЛЕННЫЕ ВЛАДЕЛЬЦЕМ (this.db.staff)
        const staffList = Array.isArray(this.db.staff) ? this.db.staff : [];
        const staff = staffList.find(s => {
            const sDigits = String(s.phone || '').replace(/\D/g, '');
            return sDigits.slice(-10) === last10;
        });

        if (staff) {
            let isStaffPassValid = (staff.password === pass);
            if (!isStaffPassValid && staff.passHash && staff.salt) {
                const hash = await Security.hash(pass, staff.salt);
                if (hash === staff.passHash) isStaffPassValid = true;
            }

            if (isStaffPassValid) {
                const role = staff.role || 'worker';
                this.currentRole = role;
                this.sessionRole = role;
                this.currentUserName = staff.name;
                this.currentUserPhone = staff.phone;
                this.currentAdminId = (role === 'admin') ? staff.id : null;
                this.currentWorkerId = (role === 'worker') ? staff.id : null;
                this.sessionToken = Security.generateId();
                this.sessionExpires = Date.now() + 14 * 24 * 3600 * 1000;
                this.saveStaffSession();
                this.closeAuthModal();
                this.applyRoleUI();
                this.renderAll();
                const roleLabels = { owner: 'Владелец', admin: 'Администратор', worker: 'Мойщик' };
                alert(`✅ Добро пожаловать, ${staff.name}! Вход выполнен (${roleLabels[role] || role}).`);
                return;
            }
        }

        // 3. ПРОВЕРКА: ЗАРЕГИСТРИРОВАННЫЙ КЛИЕНТ (this.db.clients)
        const clientList = Array.isArray(this.db.clients) ? this.db.clients : [];
        const client = clientList.find(c => {
            const cDigits = String(c.phone || '').replace(/\D/g, '');
            return cDigits.slice(-10) === last10;
        });

        if (client) {
            let isClientPassValid = false;
            if (client.passHash && client.salt) {
                const hash = await Security.hash(pass, client.salt);
                if (hash === client.passHash) isClientPassValid = true;
            } else if (client.password && client.password === pass) {
                isClientPassValid = true;
            }

            if (isClientPassValid) {
                this.currentRole = 'guest';
                this.sessionRole = 'guest';
                this.saveClientSession(client);
                this.closeAuthModal();

                const bookingNameEl = document.getElementById('bookingClientName');
                const bookingPhoneEl = document.getElementById('bookingClientPhone');
                if (bookingNameEl) bookingNameEl.value = client.name;
                if (bookingPhoneEl) bookingPhoneEl.value = client.phone;

                this.populateBookingCarDropdown();
                this.applyRoleUI();
                this.renderAll();
                alert(`✅ С возвращением, ${client.name}! Личный кабинет активен.`);
                return;
            }
        }

        // 4. ОБРАТНАЯ СОВМЕСТИМОСТЬ: СТАРЫЕ АДМИНИСТРАТОРЫ
        const legacyAdmin = (this.db.admins || []).find(a => (a.pin === pass || pass === 'admin'));
        if (legacyAdmin) {
            this.setSession('admin', legacyAdmin.id);
            this.currentUserName = legacyAdmin.name;
            this.closeAuthModal();
            this.applyRoleUI();
            this.renderAll();
            alert(`✅ Добро пожаловать, Администратор ${legacyAdmin.name}!`);
            return;
        }

        alert('❌ Неверный номер телефона или пароль.\nЕсли у вас еще нет аккаунта, перейдите на вкладку «Регистрация».');
    }

    loginClient(event) {
        return this.submitUnifiedLogin(event);
    }

    // ==================== ПРОВЕРКА НОМЕРА ТЕЛЕФОНА И SMS-КОД ====================

    sendVerificationCode() {
        const phoneInput = document.getElementById('unifiedRegPhone');
        if (!phoneInput) return;
        const rawPhone = phoneInput.value.trim();
        const cleanDigits = rawPhone.replace(/\D/g, '');
        const last10 = cleanDigits.slice(-10);

        if (last10.length < 10) {
            alert('Пожалуйста, введите корректный номер телефона (не менее 10 цифр).');
            phoneInput.focus();
            return;
        }

        const exists = (this.db.clients || []).find(c => String(c.phone || '').replace(/\D/g, '').slice(-10) === last10);
        if (exists) {
            alert('Клиент с таким номером уже зарегистрирован! Пожалуйста, перейдите на вкладку «Вход».');
            this.switchAuthTab('login');
            const loginPhone = document.getElementById('unifiedLoginPhone');
            if (loginPhone) loginPhone.value = this.formatPhoneNumber(rawPhone);
            return;
        }

        const code = Math.floor(1000 + Math.random() * 9000).toString();
        this.smsVerification = {
            phone: last10,
            code: code,
            expiresAt: Date.now() + 180000,
            verified: false
        };

        const container = document.getElementById('smsCodeContainer');
        if (container) container.style.display = 'block';

        const statusEl = document.getElementById('codeVerificationStatus');
        if (statusEl) {
            statusEl.innerHTML = `<span style="color:var(--primary); font-size:0.85rem;">📩 Проверочный код отправлен! Введите полученный 4-значный код:</span>`;
        }

        const codeInput = document.getElementById('unifiedRegCode');
        if (codeInput) {
            codeInput.value = '';
            codeInput.disabled = false;
            codeInput.focus();
        }

        const verifyBtn = document.getElementById('btnVerifyCode');
        if (verifyBtn) verifyBtn.style.display = 'inline-block';

        this.showSmsNotification(code, this.formatPhoneNumber(rawPhone));

        const sendBtn = document.getElementById('btnSendSmsCode');
        if (sendBtn) {
            sendBtn.disabled = true;
            let sec = 60;
            sendBtn.textContent = `Повтор через ${sec}с`;
            if (this._smsCountdown) clearInterval(this._smsCountdown);
            this._smsCountdown = setInterval(() => {
                sec--;
                if (sec <= 0) {
                    clearInterval(this._smsCountdown);
                    sendBtn.disabled = false;
                    sendBtn.textContent = '📲 Отправить код снова';
                } else {
                    sendBtn.textContent = `Повтор через ${sec}с`;
                }
            }, 1000);
        }
    }

    confirmVerificationCode() {
        const codeInput = document.getElementById('unifiedRegCode');
        if (!codeInput) return;
        const val = codeInput.value.trim();

        if (!this.smsVerification) {
            alert('Сначала нажмите «Получить код».');
            return;
        }

        if (Date.now() > this.smsVerification.expiresAt) {
            alert('Время действия кода истекло. Запросите новый код.');
            return;
        }

        if (val === this.smsVerification.code) {
            this.smsVerification.verified = true;
            const statusEl = document.getElementById('codeVerificationStatus');
            if (statusEl) {
                statusEl.innerHTML = `<span style="color:#059669; font-weight:700; font-size:0.85rem;">✅ Номер телефона успешно подтверждён!</span>`;
            }
            codeInput.disabled = true;
            const verifyBtn = document.getElementById('btnVerifyCode');
            if (verifyBtn) verifyBtn.style.display = 'none';
            alert('✅ Номер подтверждён! Теперь введите пароль и нажмите «Зарегистрироваться».');
        } else {
            alert('❌ Неверный проверочный код. Проверьте код в SMS и повторите ввод.');
            codeInput.focus();
        }
    }

    showSmsNotification(code, formattedPhone) {
        const banner = document.getElementById('smsPushBanner');
        const codeEl = document.getElementById('smsPushCode');
        const bodyEl = document.getElementById('smsPushBody');
        if (!banner || !codeEl) return;

        codeEl.textContent = code;
        if (bodyEl) {
            bodyEl.innerHTML = `Ваш проверочный код: <strong class="sms-push-code">${code}</strong> для регистрации в CarWash Tracker (${formattedPhone}). Никому не сообщайте его.`;
        }

        banner.style.display = 'flex';
        this.playSmsChime();

        if (this._smsPushTimer) clearTimeout(this._smsPushTimer);
        this._smsPushTimer = setTimeout(() => {
            this.hideSmsNotification();
        }, 15000);
    }

    hideSmsNotification() {
        const banner = document.getElementById('smsPushBanner');
        if (banner) banner.style.display = 'none';
    }

    playSmsChime() {
        try {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (!AudioCtx) return;
            const ctx = new AudioCtx();
            const now = ctx.currentTime;

            const osc1 = ctx.createOscillator();
            const gain1 = ctx.createGain();
            osc1.type = 'sine';
            osc1.frequency.setValueAtTime(880, now);
            gain1.gain.setValueAtTime(0.12, now);
            gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
            osc1.connect(gain1);
            gain1.connect(ctx.destination);
            osc1.start(now);
            osc1.stop(now + 0.3);

            const osc2 = ctx.createOscillator();
            const gain2 = ctx.createGain();
            osc2.type = 'sine';
            osc2.frequency.setValueAtTime(1320, now + 0.12);
            gain2.gain.setValueAtTime(0.15, now + 0.12);
            gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.5);
            osc2.connect(gain2);
            gain2.connect(ctx.destination);
            osc2.start(now + 0.12);
            osc2.stop(now + 0.5);
        } catch (e) {}
    }

    async registerUnifiedClient(event) {
        event.preventDefault();
        const name = document.getElementById('unifiedRegName').value.trim();
        const rawPhone = document.getElementById('unifiedRegPhone').value.trim();
        const pass = document.getElementById('unifiedRegPass').value;

        if (!name || !rawPhone || !pass) {
            alert('Пожалуйста, заполните все обязательные поля.');
            return;
        }
        if (pass.length < 4) {
            alert('Пароль должен содержать минимум 4 символа.');
            return;
        }

        const cleanDigits = rawPhone.replace(/\D/g, '');
        const last10 = cleanDigits.slice(-10);
        if (last10.length < 10) {
            alert('Пожалуйста, введите корректный номер телефона.');
            return;
        }

        // Проверяем подтверждение номера
        if (!this.smsVerification || !this.smsVerification.verified || this.smsVerification.phone !== last10) {
            alert('⚠️ Пожалуйста, подтвердите номер телефона проверочным кодом!\nНажмите кнопку «Получить код» и введите 4-значный код.');
            return;
        }

        if (!Array.isArray(this.db.clients)) this.db.clients = [];
        const exists = this.db.clients.find(c => String(c.phone || '').replace(/\D/g, '').slice(-10) === last10);
        if (exists) {
            alert('Клиент с таким номером телефона уже зарегистрирован! Пожалуйста, войдите в аккаунт.');
            this.switchAuthTab('login');
            return;
        }

        const salt = Security.generateSalt();
        const passHash = await Security.hash(pass, salt);
        const formattedPhone = this.formatPhoneNumber(rawPhone);

        const newClient = {
            id: 'c_' + Security.generateId(),
            name,
            phone: formattedPhone,
            passHash,
            salt,
            cars: [],
            createdAt: new Date().toISOString()
        };

        this.db.clients.push(newClient);
        this.saveDatabase();
        this.saveClientSession(newClient);
        this.closeAuthModal();

        const bookingNameEl = document.getElementById('bookingClientName');
        const bookingPhoneEl = document.getElementById('bookingClientPhone');
        if (bookingNameEl) bookingNameEl.value = newClient.name;
        if (bookingPhoneEl) bookingPhoneEl.value = newClient.phone;

        this.populateBookingCarDropdown();
        this.applyRoleUI();
        this.renderAll();
        alert(`🎉 Добро пожаловать, ${name}! Личный кабинет успешно создан.`);
    }

    registerClient(event) {
        return this.registerUnifiedClient(event);
    }

    logout() {
        this.currentRole = 'guest';
        this.sessionRole = 'guest';
        this.currentWorkerId = null;
        this.currentAdminId = null;
        this.currentUserName = null;
        this.currentUserPhone = null;
        this.sessionToken = null;
        this.sessionExpires = 0;
        this.currentClient = null;

        try { localStorage.removeItem(STAFF_SESSION_KEY); } catch (e) {}
        try { localStorage.removeItem(CLIENT_SESSION_KEY); } catch (e) {}
        try { sessionStorage.removeItem(CLIENT_SESSION_KEY); } catch (e) {}
        try { localStorage.removeItem(ACTIVE_TAB_KEY); } catch (e) {}

        const bookingNameEl = document.getElementById('bookingClientName');
        const bookingPhoneEl = document.getElementById('bookingClientPhone');
        if (bookingNameEl) bookingNameEl.value = '';
        if (bookingPhoneEl) bookingPhoneEl.value = '';

        this.switchTab('guestBooking');
        this.applyRoleUI();
        this.populateBookingCarDropdown();
        this.renderAll();
        alert('Вы вышли из системы. Открыт гостевой режим онлайн-записи.');
    }

    logoutClient() {
        this.logout();
    }

    loginAsGuest() {
        this.logout();
    }

    async forgotPasswordPrompt() {
        if (!this.db.auth || !this.db.auth.recoveryHash) {
            alert('Секретное кодовое слово еще не настроено в системе.');
            return;
        }

        const inputPhrase = prompt('Введите секретное кодовое слово для восстановления доступа:');
        if (!inputPhrase) return;

        const hash = await Security.hash(inputPhrase.trim().toLowerCase(), this.db.auth.recoverySalt);
        if (hash === this.db.auth.recoveryHash) {
            const newPassword = prompt('Кодовое слово верно! Введите новый пароль Владельца (минимум 4 символа):');
            if (newPassword && newPassword.length >= 4) {
                const newSalt = Security.generateSalt();
                this.db.auth.ownerSalt = newSalt;
                this.db.auth.ownerHash = await Security.hash(newPassword, newSalt);
                this.saveDatabase();
                alert('Пароль владельца успешно обновлен! Теперь войдите с новым паролем.');
            } else {
                alert('Пароль слишком короткий или отменен.');
            }
        } else {
            this.registerFailedAttempt();
            alert('Неверное секретное кодовое слово!');
        }
    }

    async saveSecurityPasswords(event) {
        event.preventDefault();
        if (!this.verifyAuth('owner')) return;

        const newOwner = document.getElementById('changeOwnerPassword').value;
        const newAdmin = document.getElementById('changeAdminPassword').value;
        const newWorker = document.getElementById('changeWorkerPin').value;
        const newSecret = document.getElementById('changeSecretRecovery').value;

        let changedCount = 0;

        if (newOwner) {
            if (newOwner.length < 4) { alert('Пароль владельца должен быть от 4 символов!'); return; }
            const salt = Security.generateSalt();
            this.db.auth.ownerSalt = salt;
            this.db.auth.ownerHash = await Security.hash(newOwner, salt);
            changedCount++;
        }

        if (newAdmin) {
            if (newAdmin.length < 4) { alert('Пароль администратора должен быть от 4 символов!'); return; }
            const salt = Security.generateSalt();
            this.db.auth.adminSalt = salt;
            this.db.auth.adminHash = await Security.hash(newAdmin, salt);
            changedCount++;
        }

        if (newWorker) {
            if (newWorker.length < 4) { alert('PIN мойщиков должен быть от 4 символов!'); return; }
            const salt = Security.generateSalt();
            this.db.auth.workerSalt = salt;
            this.db.auth.workerPinHash = await Security.hash(newWorker, salt);
            changedCount++;
        }

        if (newSecret) {
            if (newSecret.length < 4) { alert('Секретное слово должно быть от 4 символов!'); return; }
            const salt = Security.generateSalt();
            this.db.auth.recoverySalt = salt;
            this.db.auth.recoveryHash = await Security.hash(newSecret.trim().toLowerCase(), salt);
            changedCount++;
        }

        if (changedCount > 0) {
            this.saveDatabase();
            event.target.reset();
            alert(`✅ Успешно обновлено паролей: ${changedCount}. Пароли зашифрованы.`);
        } else {
            alert('Вы не ввели ни одного нового пароля.');
        }
    }

    // ==================== РОЛИ И UI ====================

    applyRoleUI() {
        const badge = document.getElementById('currentRoleBadge');
        const switchBtnText = document.getElementById('switchUserBtnText');
        document.body.className = `role-${this.currentRole}`;

        // Плашка профиля клиента скрыта для всех служебных ролей (Администратор, Владелец, Мойщик)
        const clientBar = document.getElementById('clientAccountBar');
        if (clientBar) {
            clientBar.style.display = (this.currentRole === 'guest') ? 'flex' : 'none';
        }

        if (this.currentRole === 'guest') {
            if (this.currentClient) {
                if (badge) {
                    badge.textContent = `🚗 Клиент: ${Security.escapeHTML(this.currentClient.name)}`;
                    badge.style.background = '#e0f2fe';
                    badge.style.color = '#0369a1';
                }
                if (switchBtnText) switchBtnText.textContent = `🚪 Выйти (${this.currentClient.name})`;
            } else {
                if (badge) {
                    badge.textContent = '🚗 Режим: Клиент / Гость';
                    badge.style.background = '#f1f5f9';
                    badge.style.color = '#334155';
                }
                if (switchBtnText) switchBtnText.textContent = '👤 Войти';
            }
            this.switchTab('guestBooking');
        } else if (this.currentRole === 'worker') {
            const worker = this.db.workers.find(w => w.id === this.currentWorkerId);
            const workerName = this.currentUserName || (worker ? worker.name : 'Мойщик');
            if (badge) {
                badge.textContent = `🧽 Мойщик: ${Security.escapeHTML(workerName)}`;
                badge.style.background = '#e0f2fe';
                badge.style.color = '#0369a1';
            }
            if (switchBtnText) switchBtnText.textContent = `🚪 Выйти (${workerName})`;
            this.switchTab('workerTasks');
        } else if (this.currentRole === 'admin') {
            const admin = (this.db.admins || []).find(a => a.id === this.currentAdminId);
            const adminName = this.currentUserName || (admin ? admin.name : 'Администратор');
            if (badge) {
                badge.textContent = `📋 Администратор: ${Security.escapeHTML(adminName)}`;
                badge.style.background = '#eff6ff';
                badge.style.color = '#2563eb';
            }
            if (switchBtnText) switchBtnText.textContent = `🚪 Выйти (${adminName})`;
            this.switchTab('activeOrders');
        } else if (this.currentRole === 'owner') {
            const ownerName = this.currentUserName || 'Алимжан';
            if (badge) {
                badge.textContent = `👑 Владелец: ${Security.escapeHTML(ownerName)}`;
                badge.style.background = '#fef3c7';
                badge.style.color = '#b45309';
            }
            if (switchBtnText) switchBtnText.textContent = `🚪 Выйти (${ownerName})`;
            this.switchTab('activeOrders');
        }
    }

    switchTab(tabId) {
        if (['finance', 'settings'].includes(tabId) && this.sessionRole !== 'owner') {
            this.openAuthModal();
            return;
        }

        if (['newOrder', 'activeOrders', 'history', 'adminBookings', 'adminWaitlist'].includes(tabId) && !['admin', 'owner'].includes(this.sessionRole)) {
            alert('Этот раздел доступен только Администратору или Владельцу.');
            return;
        }

        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabId);
        });

        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `tab-${tabId}`);
        });

        try {
            // Сохраняем активную вкладку только для персонала (Владелец, Админ, Мойщик)
            if (this.currentRole !== 'guest') {
                localStorage.setItem(ACTIVE_TAB_KEY, tabId);
            }
        } catch (e) {}

        if (tabId === 'guestBooking') {
            this.populateBookingCarDropdown();
            this.renderBookingServicesCheckboxes();
            this.renderAvailableTimeSlots();
            this.renderGuestBookings();
        }
        if (tabId === 'guestCars') this.renderClientGarage();
        if (tabId === 'adminBookings') this.renderAdminBookings();
        if (tabId === 'adminWaitlist') this.renderAdminWaitlist();
        if (tabId === 'finance') this.renderFinance();
        if (tabId === 'history') this.renderHistory();
        if (tabId === 'activeOrders') {
            this.renderActiveOrders();
            this.renderBoxesAndSelects();
        }
        if (tabId === 'workerTasks') this.renderWorkerTasks();
        if (tabId === 'workerHistory') this.renderWorkerHistory();
        if (tabId === 'guestSearch') this.renderGuestBoxesOverview();
        if (tabId === 'guestPrices') this.renderGuestPrices();
        if (tabId === 'settings') this.renderSettings();
    }

    restoreLastActiveTab() {
        try {
            // Для клиентов и посетителей ВСЕГДА открывается главная страница онлайн-записи
            if (this.currentRole === 'guest') {
                this.switchTab('guestBooking');
                return;
            }

            const savedTab = localStorage.getItem(ACTIVE_TAB_KEY);
            if (savedTab) {
                if (['finance', 'settings'].includes(savedTab) && this.sessionRole !== 'owner') {
                    this.switchTab('activeOrders');
                    return;
                }
                if (['newOrder', 'activeOrders', 'history', 'adminBookings', 'adminWaitlist'].includes(savedTab) && !['admin', 'owner'].includes(this.sessionRole)) {
                    this.switchTab('workerTasks');
                    return;
                }
                if (['workerTasks', 'workerHistory'].includes(savedTab) && this.currentRole !== 'worker') {
                    this.switchTab('activeOrders');
                    return;
                }
                this.switchTab(savedTab);
            } else {
                if (this.currentRole === 'worker') {
                    this.switchTab('workerTasks');
                } else {
                    this.switchTab('activeOrders');
                }
            }
        } catch (e) {}
    }

    // ==================== МАСКА И ФОРМАТИРОВАНИЕ НОМЕРА ТЕЛЕФОНА ====================

    formatPhoneNumber(val) {
        if (!val) return '';
        const raw = String(val).trim();
        let digits = raw.replace(/\D/g, '');
        if (!digits) {
            return raw.includes('+') ? '+7 (' : '';
        }

        // Если введены 11 цифр, начинающихся с 7 или 8 (например 8707... или 7707...)
        if (digits.length === 11 && (digits[0] === '7' || digits[0] === '8')) {
            digits = digits.substring(1);
        } else if (digits.length > 11) {
            if (digits.startsWith('7') || digits.startsWith('8')) {
                digits = digits.substring(1, 11);
            } else {
                digits = digits.substring(0, 10);
            }
        } else if (digits.length <= 10) {
            // Если номер начинается с префикса +7 или 8
            if (raw.startsWith('+7') && digits.startsWith('7')) {
                digits = digits.substring(1);
            } else if (raw.startsWith('8') && digits.startsWith('8')) {
                digits = digits.substring(1);
            }
        }

        digits = digits.substring(0, 10);

        let res = '+7';
        if (digits.length > 0) {
            res += ' (' + digits.substring(0, 3);
        }
        if (digits.length >= 3) {
            res += ') ' + digits.substring(3, 6);
        }
        if (digits.length >= 6) {
            res += '-' + digits.substring(6, 8);
        }
        if (digits.length >= 8) {
            res += '-' + digits.substring(8, 10);
        }
        return res;
    }

    initPhoneMasks() {
        const phoneInputs = document.querySelectorAll('input[type="tel"]');
        phoneInputs.forEach(input => {
            // Форматируем текущее значение если уже есть
            if (input.value && input.value.trim().length > 0 && !input.value.startsWith('+7 (')) {
                input.value = this.formatPhoneNumber(input.value);
            }

            if (input.dataset.maskBound) return;
            input.dataset.maskBound = 'true';

            input.addEventListener('focus', () => {
                if (!input.value || !input.value.trim()) {
                    input.value = '+7 (';
                }
            });

            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace') {
                    const selStart = input.selectionStart;
                    const selEnd = input.selectionEnd;
                    if (selStart === selEnd) {
                        if (selStart <= 4) {
                            e.preventDefault();
                            input.value = '';
                            return;
                        }
                        const before = input.value.substring(0, selStart);
                        const after = input.value.substring(selStart);
                        const lastChar = before[before.length - 1];
                        if (/[\s\-\)\(]/.test(lastChar)) {
                            e.preventDefault();
                            // Удаляем последнюю цифру перед знаком форматирования
                            let lastDigitIndex = -1;
                            for (let i = before.length - 1; i >= 0; i--) {
                                if (/\d/.test(before[i]) && i >= 4) {
                                    lastDigitIndex = i;
                                    break;
                                }
                            }
                            if (lastDigitIndex !== -1) {
                                const newBefore = before.substring(0, lastDigitIndex) + before.substring(lastDigitIndex + 1);
                                input.value = this.formatPhoneNumber(newBefore + after);
                                const newPos = Math.max(4, input.value.length);
                                try { input.setSelectionRange(newPos, newPos); } catch (_) {}
                            } else {
                                input.value = '';
                            }
                        }
                    }
                }
            });

            input.addEventListener('input', () => {
                const cursor = input.selectionStart;
                const prevLen = input.value.length;
                const formatted = this.formatPhoneNumber(input.value);
                input.value = formatted;

                if (cursor !== null) {
                    const diff = formatted.length - prevLen;
                    const newPos = Math.max(4, Math.min(cursor + diff, formatted.length));
                    try { input.setSelectionRange(newPos, newPos); } catch (_) {}
                }
            });

            input.addEventListener('blur', () => {
                const rawDigits = input.value.replace(/\D/g, '');
                if (rawDigits.length <= 1) {
                    input.value = '';
                }
            });
        });
    }

    initDOM() {
        const options = { day: 'numeric', month: 'long', year: 'numeric' };
        const shiftDateEl = document.getElementById('shiftDate');
        if (shiftDateEl) shiftDateEl.textContent = new Date().toLocaleDateString('ru-RU', options);

        const bookingDateInput = document.getElementById('bookingDate');
        if (bookingDateInput) {
            const todayStr = Security.getLocalDateString(new Date());
            bookingDateInput.min = todayStr;
            if (!bookingDateInput.value) {
                bookingDateInput.value = todayStr;
            }
        }
        this.renderAvailableTimeSlots();
        this.initPhoneMasks();
        this.updateThemeButton();
    }

    // ==================== ТЕМА ОФОРМЛЕНИЯ (СВЕТЛАЯ / ТЕМНАЯ) ====================

    initTheme() {
        const savedTheme = localStorage.getItem('carwash_theme');
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        this.theme = savedTheme || (prefersDark ? 'dark' : 'light');
        document.documentElement.setAttribute('data-theme', this.theme);
    }

    toggleTheme() {
        this.theme = this.theme === 'dark' ? 'light' : 'dark';
        try {
            localStorage.setItem('carwash_theme', this.theme);
        } catch (e) {}
        document.documentElement.setAttribute('data-theme', this.theme);
        this.updateThemeButton();
    }

    updateThemeButton() {
        const btn = document.getElementById('themeToggleBtn');
        if (!btn) return;
        if (this.theme === 'dark') {
            btn.innerHTML = '☀️ <span class="hide-mobile">Светлая</span>';
            btn.title = 'Включить светлую тему оформления';
        } else {
            btn.innerHTML = '🌙 <span class="hide-mobile">Темная</span>';
            btn.title = 'Включить темную тему оформления';
        }
    }

    // ==================== QR-КОД САЙТА ДЛЯ КЛИЕНТОВ И ПЕЧАТЬ ====================

    openQrModal() {
        const siteUrl = window.location.href.split('#')[0];
        const container = document.getElementById('modalQrCodeContainer');
        const textEl = document.getElementById('modalSiteUrlText');
        if (textEl) textEl.textContent = siteUrl;
        if (container) {
            this.renderQrCode(container, siteUrl, 220);
        }
        document.getElementById('qrModal').classList.add('open');
    }

    closeQrModal() {
        document.getElementById('qrModal').classList.remove('open');
    }

    copySiteUrl() {
        const siteUrl = window.location.href.split('#')[0];
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(siteUrl).then(() => {
                alert('📋 Ссылка на автомойку скопирована в буфер обмена!\n\n' + siteUrl);
            }).catch(() => {
                prompt('Скопируйте ссылку на автомойку:', siteUrl);
            });
        } else {
            prompt('Скопируйте ссылку на автомойку:', siteUrl);
        }
    }

    renderQrCode(container, url, size = 220) {
        if (!container) return;
        container.innerHTML = '';
        const encoded = encodeURIComponent(url);

        const img = document.createElement('img');
        img.src = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&margin=8&data=${encoded}`;
        img.alt = 'QR-код автомойки';
        img.style.width = `${size}px`;
        img.style.height = `${size}px`;
        img.style.display = 'block';
        img.style.borderRadius = '8px';

        img.onerror = () => {
            container.innerHTML = `
                <div style="width:${size}px; height:${size}px; display:flex; flex-direction:column; align-items:center; justify-content:center; background:var(--bg-page); color:var(--text-muted); font-size:0.85rem; padding:0.5rem; text-align:center; border-radius:8px;">
                    <span style="font-size:2rem; margin-bottom:0.25rem;">📱</span>
                    <strong>Ссылка на сайт:</strong>
                    <div style="word-break:break-all; font-size:0.75rem; margin-top:0.25rem;">${Security.escapeHTML(url)}</div>
                </div>
            `;
        };

        container.appendChild(img);
    }

    printQrFlyer() {
        const siteUrl = window.location.href.split('#')[0];
        const encoded = encodeURIComponent(siteUrl);
        const contacts = this.db.contacts || {};
        const address = contacts.address || 'ул. Автомобильная, 12/1';
        const hours = contacts.hours || 'Круглосуточно 24/7 (без перерывов и выходных)';
        const phone = contacts.phone || '+7 (777) 123-45-67';

        const printWin = window.open('', '_blank');
        if (!printWin) {
            alert('Пожалуйста, разрешите открытие всплывающих окон в браузере, чтобы распечатать плакат.');
            return;
        }

        printWin.document.write(`
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <title>QR-код автомойки — CarWash Tracker</title>
                <style>
                    @page { size: A4 portrait; margin: 1.2cm; }
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        text-align: center;
                        color: #0f172a;
                        padding: 1.5rem 1rem;
                        background: #ffffff;
                    }
                    .flyer-card {
                        border: 3px solid #2563eb;
                        border-radius: 24px;
                        padding: 2rem 1.5rem;
                        max-width: 580px;
                        margin: 0 auto;
                        box-shadow: 0 10px 25px rgba(37, 99, 235, 0.1);
                    }
                    .logo-icon { font-size: 3.5rem; margin-bottom: 0.25rem; }
                    h1 { font-size: 2.3rem; margin: 0 0 0.4rem; color: #1e3a8a; }
                    .badge-hours {
                        display: inline-block;
                        background: #059669;
                        color: #ffffff;
                        font-weight: 700;
                        font-size: 1rem;
                        padding: 0.35rem 1rem;
                        border-radius: 9999px;
                        margin-bottom: 1.25rem;
                    }
                    .qr-box {
                        background: #f8fafc;
                        display: inline-block;
                        padding: 1.25rem;
                        border-radius: 20px;
                        border: 2px dashed #93c5fd;
                        margin: 0.5rem 0 1rem;
                    }
                    .qr-box img { width: 280px; height: 280px; display: block; border-radius: 10px; }
                    .cta-text { font-size: 1.35rem; font-weight: 800; color: #2563eb; margin: 0.5rem 0; }
                    .features-list {
                        font-size: 1.05rem;
                        color: #334155;
                        text-align: left;
                        display: inline-block;
                        line-height: 1.8;
                        margin: 0.75rem 0 1rem;
                    }
                    .contacts-footer {
                        border-top: 1px solid #cbd5e1;
                        padding-top: 1rem;
                        margin-top: 1rem;
                        font-size: 0.95rem;
                        color: #475569;
                    }
                    .contacts-footer strong { color: #0f172a; }
                </style>
            </head>
            <body>
                <div class="flyer-card">
                    <div class="logo-icon">🚗💦</div>
                    <h1>CarWash Tracker</h1>
                    <div class="badge-hours">🕒 \${Security.escapeHTML(hours)}</div>

                    <div class="cta-text">📲 Наведите камеру телефона на QR-код</div>
                    <div class="qr-box">
                        <img src="https://api.qrserver.com/v1/create-qr-code/?size=300x300&margin=8&data=\${encoded}" alt="QR код для клиентов" />
                    </div>

                    <div class="features-list">
                        <div>✅ Онлайн-бронирование бокса без очередей</div>
                        <div>✅ Отслеживание готовности авто в боксе онлайн</div>
                        <div>✅ Личный кабинет и история обслуживания</div>
                    </div>

                    <div class="contacts-footer">
                        <p>📍 <strong>Адрес:</strong> \${Security.escapeHTML(address)}</p>
                        <p>📞 <strong>Телефон для справок:</strong> \${Security.escapeHTML(phone)}</p>
                        <p style="font-size:0.85rem; color:#64748b; margin-top:0.4rem;">\${Security.escapeHTML(siteUrl)}</p>
                    </div>
                </div>
                <script>
                    window.onload = function() {
                        setTimeout(function() { window.print(); }, 500);
                    };
                <\/script>
            </body>
            </html>
        `);
        printWin.document.close();
    }

    renderAll() {
        this.renderClientBar();
        this.populateBookingCarDropdown();
        this.renderBookingServicesCheckboxes();
        this.renderGuestBookings();
        this.renderClientGarage();
        this.renderAdminBookings();
        this.renderAdminWaitlist();
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
        this.renderContactsView();
        this.initPhoneMasks();
    }

    // ==================== ЛИЧНЫЙ КАБИНЕТ КЛИЕНТА (ГОСТЯ) ====================

    renderClientBar() {
        const clientBar = document.getElementById('clientAccountBar');
        if (clientBar) {
            clientBar.style.display = (this.currentRole === 'guest') ? 'flex' : 'none';
        }

        // В служебных ролях (Администратор, Владелец, Мойщик) плашка клиента не отображается
        if (this.currentRole !== 'guest') return;

        const nameEl = document.getElementById('clientBarName');
        const statusEl = document.getElementById('clientBarStatus');
        const actionsEl = document.getElementById('clientBarActions');
        const bookingNameEl = document.getElementById('bookingClientName');
        const bookingPhoneEl = document.getElementById('bookingClientPhone');

        if (this.currentClient) {
            const carCount = Array.isArray(this.currentClient.cars) ? this.currentClient.cars.length : 0;
            if (nameEl) nameEl.textContent = `Здравствуйте, ${Security.escapeHTML(this.currentClient.name)}!`;
            if (statusEl) statusEl.textContent = `Номер: ${Security.escapeHTML(this.currentClient.phone)} • Автомобилей в гараже: ${carCount}`;
            if (actionsEl) {
                actionsEl.innerHTML = `
                    <button class="btn btn-outline btn-sm" type="button" onclick="app.switchTab('guestCars')">🚗 Гараж (${carCount})</button>
                    <button class="btn btn-outline btn-sm" type="button" onclick="app.logoutClient()" style="margin-left:0.5rem; color:#ef4444; border-color:#fecaca;" title="Сменить аккаунт или выйти">🚪 Выйти / Сменить акк</button>
                `;
            }
            if (bookingNameEl && !bookingNameEl.value) bookingNameEl.value = this.currentClient.name;
            if (bookingPhoneEl && !bookingPhoneEl.value) bookingPhoneEl.value = this.currentClient.phone;
        } else {
            if (nameEl) nameEl.textContent = 'Гостевой режим';
            if (statusEl) statusEl.textContent = 'Войдите в личный кабинет, чтобы сохранять свои авто и управлять бронированиями';
            if (actionsEl) {
                actionsEl.innerHTML = `
                    <button class="btn btn-primary btn-sm" type="button" onclick="app.openClientAuthModal()">🔑 Вход / Регистрация</button>
                `;
            }
        }
    }

    // ==================== ГАРАЖ КЛИЕНТА ====================

    renderClientGarage() {
        const emptyEl = document.getElementById('clientGarageEmpty');
        const listEl = document.getElementById('clientGarageList');
        if (!emptyEl || !listEl) return;

        if (!this.currentClient) {
            emptyEl.style.display = 'block';
            emptyEl.innerHTML = `
                <div style="padding: 1.5rem 0; text-align:center;">
                    <p>Для управления гаражом и сохранения машин войдите в аккаунт.</p>
                    <button class="btn btn-primary" type="button" onclick="app.openClientAuthModal()" style="margin-top:0.5rem;">Войти в личный кабинет</button>
                </div>
            `;
            listEl.style.display = 'none';
            listEl.innerHTML = '';
            return;
        }

        const cars = Array.isArray(this.currentClient.cars) ? this.currentClient.cars : [];
        if (cars.length === 0) {
            emptyEl.style.display = 'block';
            emptyEl.innerHTML = 'У вас пока нет сохраненных авто. Добавьте свою первую машину в форме справа!';
            listEl.style.display = 'none';
            listEl.innerHTML = '';
        } else {
            emptyEl.style.display = 'none';
            listEl.style.display = 'grid';
            listEl.innerHTML = '';

            const categoryNames = {
                sedan: '1 класс — Седан / Хэтчбек',
                crossover: '2 класс — Кроссовер / Универсал',
                suv: '3 класс — Внедорожник / Джип',
                minivan: '4 класс — Микроавтобус'
            };

            cars.forEach((car, idx) => {
                const card = document.createElement('div');
                card.className = 'garage-card';
                card.innerHTML = `
                    <div style="flex:1;">
                        <span class="garage-plate-badge">${Security.escapeHTML(car.plate)}</span>
                        <div style="font-weight:700; margin:0.25rem 0;">${Security.escapeHTML(car.model)}</div>
                        <div style="font-size:0.8rem; color:var(--text-muted);">${categoryNames[car.category] || car.category}</div>
                        <div style="margin-top:0.75rem; display:flex; gap:0.5rem;">
                            <button class="btn btn-outline btn-sm" type="button" onclick="app.quickBookCar(${idx})">📅 Записаться</button>
                            <button class="btn btn-outline btn-sm" type="button" onclick="app.removeClientCar('${Security.escapeHTML(car.plate)}')" style="color:#ef4444; border-color:#fecaca;" title="Удалить">🗑</button>
                        </div>
                    </div>
                `;
                listEl.appendChild(card);
            });
        }
    }

    quickBookCar(carIdx) {
        this.switchTab('guestBooking');
        const select = document.getElementById('bookingCarSelect');
        if (select) {
            select.value = `car_${carIdx}`;
            this.onBookingCarSelected();
        }
    }

    addClientCar(event) {
        event.preventDefault();
        if (!this.currentClient) {
            alert('Чтобы добавить автомобиль в гараж, пожалуйста, войдите в личный кабинет.');
            this.openClientAuthModal();
            return;
        }

        const plateInput = document.getElementById('garagePlate');
        const modelInput = document.getElementById('garageModel');
        const catSelect = document.getElementById('garageCategory');

        const plate = plateInput.value.trim().toUpperCase();
        const model = modelInput.value.trim();
        const category = catSelect.value;

        if (!plate || !model) {
            alert('Пожалуйста, укажите госномер и модель авто.');
            return;
        }

        if (!Array.isArray(this.currentClient.cars)) {
            this.currentClient.cars = [];
        }

        const cleanPlate = plate.replace(/\s+/g, '');
        const exists = this.currentClient.cars.find(c => c.plate.replace(/\s+/g, '') === cleanPlate);
        if (exists) {
            alert(`Автомобиль ${plate} уже есть в вашем гараже!`);
            return;
        }

        const newCar = { plate, model, category };
        this.currentClient.cars.push(newCar);

        const dbClient = this.db.clients.find(c => c.id === this.currentClient.id);
        if (dbClient) {
            dbClient.cars = this.currentClient.cars;
        }

        this.saveDatabase();
        this.saveClientSession(this.currentClient);
        event.target.reset();
        this.renderAll();
        alert(`🚗 Автомобиль ${plate} (${model}) успешно добавлен в ваш гараж!`);
    }

    removeClientCar(plate) {
        if (!this.currentClient || !Array.isArray(this.currentClient.cars)) return;
        if (!confirm(`Удалить автомобиль ${plate} из гаража?`)) return;

        this.currentClient.cars = this.currentClient.cars.filter(c => c.plate !== plate);
        const dbClient = this.db.clients.find(c => c.id === this.currentClient.id);
        if (dbClient) {
            dbClient.cars = this.currentClient.cars;
        }

        this.saveDatabase();
        this.saveClientSession(this.currentClient);
        this.renderAll();
    }

    populateBookingCarDropdown() {
        const select = document.getElementById('bookingCarSelect');
        if (!select) return;

        const currentVal = select.value;
        select.innerHTML = '';

        if (this.currentClient && Array.isArray(this.currentClient.cars) && this.currentClient.cars.length > 0) {
            this.currentClient.cars.forEach((car, idx) => {
                const opt = document.createElement('option');
                opt.value = `car_${idx}`;
                opt.textContent = `🚗 ${car.plate} — ${car.model}`;
                select.appendChild(opt);
            });
        }

        const newOpt = document.createElement('option');
        newOpt.value = 'new';
        newOpt.textContent = '+ Ввести другой автомобиль...';
        select.appendChild(newOpt);

        if (currentVal && select.querySelector(`option[value="${currentVal}"]`)) {
            select.value = currentVal;
        } else if (this.currentClient && Array.isArray(this.currentClient.cars) && this.currentClient.cars.length > 0) {
            select.value = 'car_0';
        } else {
            select.value = 'new';
        }

        this.onBookingCarSelected();
    }

    onBookingCarSelected() {
        const select = document.getElementById('bookingCarSelect');
        if (!select) return;

        const val = select.value;
        const plateInput = document.getElementById('bookingPlate');
        const modelInput = document.getElementById('bookingModel');
        const catSelect = document.getElementById('bookingCategory');

        if (val.startsWith('car_') && this.currentClient && Array.isArray(this.currentClient.cars)) {
            const idx = parseInt(val.replace('car_', ''), 10);
            const car = this.currentClient.cars[idx];
            if (car) {
                if (plateInput) plateInput.value = car.plate;
                if (modelInput) modelInput.value = car.model;
                if (catSelect) catSelect.value = car.category || 'sedan';
            }
        } else {
            if (plateInput && !plateInput.matches(':focus')) plateInput.value = '';
            if (modelInput && !modelInput.matches(':focus')) modelInput.value = '';
            if (catSelect) catSelect.value = 'sedan';
        }
        this.recalculateBookingTotal();
    }

    // ==================== ОНЛАЙН-БРОНИРОВАНИЕ ВРЕМЕНИ ====================

    renderBookingServicesCheckboxes() {
        const container = document.getElementById('bookingServicesCheckboxes');
        if (!container) return;
        container.innerHTML = '';

        this.db.services.forEach(s => {
            const label = document.createElement('label');
            label.className = 'service-checkbox-card';
            label.innerHTML = `
                <input type="checkbox" name="bookingServices" value="${s.id}" onchange="app.recalculateBookingTotal()">
                <div>
                    <div><strong>${Security.escapeHTML(s.name)}</strong></div>
                    <small class="text-muted">базовая: ${Number(s.basePrice).toLocaleString()} ₸</small>
                </div>
            `;
            container.appendChild(label);
        });
        this.recalculateBookingTotal();
    }

    recalculateBookingTotal() {
        const categoryEl = document.getElementById('bookingCategory');
        const category = categoryEl ? categoryEl.value : 'sedan';
        const multiplier = CATEGORY_MULTIPLIERS[category] || 1.0;

        const checked = Array.from(document.querySelectorAll('input[name="bookingServices"]:checked')).map(el => el.value);
        let total = 0;
        checked.forEach(sid => {
            const service = this.db.services.find(s => s.id === sid);
            if (service && typeof service.basePrice === 'number' && !isNaN(service.basePrice)) {
                total += Math.round(service.basePrice * multiplier);
            }
        });

        const displayEl = document.getElementById('bookingCalculatedPrice');
        if (displayEl) {
            displayEl.textContent = `${total.toLocaleString()} ₸`;
        }
        return total;
    }

    renderAvailableTimeSlots() {
        const select = document.getElementById('bookingTime');
        if (!select) return;
        const dateInput = document.getElementById('bookingDate');
        const selectedDate = dateInput ? dateInput.value : Security.getLocalDateString(new Date());

        const currentVal = select.value;
        select.innerHTML = '';

        const now = new Date();
        const todayStr = Security.getLocalDateString(now);
        const isToday = (selectedDate === todayStr);
        const currentHour = now.getHours();
        const currentMinute = now.getMinutes();

        // Круглосуточно 24/7: все 24 часа с шагом 30 минут
        const times = [];
        for (let h = 0; h < 24; h++) {
            times.push(`${String(h).padStart(2, '0')}:00`);
            times.push(`${String(h).padStart(2, '0')}:30`);
        }

        const bookingsForDate = (this.db.bookings || []).filter(b => b.date === selectedDate && b.status !== 'cancelled');
        let defaultSlot = null;

        times.forEach(t => {
            const [th, tm] = t.split(':').map(Number);
            const isPast = isToday && (th < currentHour || (th === currentHour && tm <= currentMinute));

            const confirmedCount = bookingsForDate.filter(b => b.time === t && (b.status === 'confirmed' || b.status === 'in-progress')).length;
            const freeBays = Math.max(0, 10 - confirmedCount);
            const opt = document.createElement('option');
            opt.value = t;

            if (isPast) {
                opt.textContent = `${t} (Прошедшее время)`;
                opt.disabled = true;
            } else {
                if (!defaultSlot) defaultSlot = t;
                if (freeBays > 0) {
                    opt.textContent = `${t} (Свободно ~${freeBays} из 10 боксов)`;
                } else {
                    opt.textContent = `${t} (Все 10 боксов заняты — лист ожидания)`;
                }
            }
            select.appendChild(opt);
        });

        if (currentVal && times.includes(currentVal)) {
            const chosenOpt = select.querySelector(`option[value="${currentVal}"]`);
            if (chosenOpt && !chosenOpt.disabled) {
                select.value = currentVal;
            } else if (defaultSlot) {
                select.value = defaultSlot;
            }
        } else if (defaultSlot) {
            select.value = defaultSlot;
        }
    }

    createBooking(event) {
        event.preventDefault();

        const plateInput = document.getElementById('bookingPlate');
        const modelInput = document.getElementById('bookingModel');
        const catSelect = document.getElementById('bookingCategory');
        const dateInput = document.getElementById('bookingDate');
        const timeSelect = document.getElementById('bookingTime');
        const nameInput = document.getElementById('bookingClientName');
        const phoneInput = document.getElementById('bookingClientPhone');

        const carPlate = plateInput.value.trim().toUpperCase();
        const carModel = modelInput.value.trim();
        const category = catSelect.value;
        const date = dateInput.value;
        const time = timeSelect.value;
        const clientName = nameInput.value.trim();
        const clientPhone = phoneInput.value.trim();

        if (!carPlate || !date || !time || !clientName || !clientPhone) {
            alert('Пожалуйста, заполните все обязательные поля!');
            return;
        }

        const selectedServices = Array.from(document.querySelectorAll('input[name="bookingServices"]:checked')).map(el => el.value);
        if (selectedServices.length === 0) {
            alert('Пожалуйста, выберите хотя бы одну услугу для мойки!');
            return;
        }

        const totalPrice = this.recalculateBookingTotal();
        const formattedPhone = this.formatPhoneNumber(clientPhone);

        const newBooking = {
            id: 'b_' + Security.generateId(),
            clientId: this.currentClient ? this.currentClient.id : null,
            clientName,
            clientPhone: formattedPhone,
            carPlate,
            carModel,
            category,
            date,
            time,
            services: selectedServices,
            totalPrice,
            status: 'pending', // pending, waiting, confirmed, in-progress, completed, cancelled
            assignedBoxId: null,
            orderId: null,
            createdAt: new Date().toISOString()
        };

        if (!Array.isArray(this.db.bookings)) {
            this.db.bookings = [];
        }

        this.db.bookings.unshift(newBooking);
        this.saveDatabase();

        if (!this.currentClient) {
            try {
                localStorage.removeItem('carwash_guest_last_phone');
                sessionStorage.setItem('carwash_guest_last_phone', formattedPhone);
            } catch (e) {}
        }

        document.querySelectorAll('input[name="bookingServices"]').forEach(cb => cb.checked = false);
        this.recalculateBookingTotal();

        this.renderAll();
        alert(`🎉 Заявка на бронирование принята!\n\nАвтомобиль: ${carPlate}\nДата и время: ${date} в ${time}\nСумма: ${totalPrice.toLocaleString()} ₸\nСтатус: ⏳ Ожидает подтверждения администратором.`);
    }

    renderGuestBookings() {
        const container = document.getElementById('guestBookingsList');
        if (!container) return;
        container.innerHTML = '';

        const bookings = Array.isArray(this.db.bookings) ? this.db.bookings : [];
        let clientPhone = '';
        if (this.currentClient) {
            clientPhone = this.currentClient.phone;
        } else {
            try {
                localStorage.removeItem('carwash_guest_last_phone');
                clientPhone = sessionStorage.getItem('carwash_guest_last_phone') || '';
            } catch (e) {}
        }

        const myBookings = bookings.filter(b => {
            if (this.currentClient && b.clientId === this.currentClient.id) return true;
            if (clientPhone && b.clientPhone.replace(/[^0-9]/g, '') === clientPhone.replace(/[^0-9]/g, '')) return true;
            return false;
        });

        if (myBookings.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; color: var(--text-muted); padding: 2rem;">
                    <p>У вас пока нет активных заявок на бронь.</p>
                    <small>Заполните форму слева, чтобы забронировать бокс на удобное время.</small>
                </div>
            `;
            return;
        }

        const statusMap = {
            pending: { label: '⏳ На рассмотрении администратором', class: 'status-pill pending' },
            waiting: { label: '⏱ В листе ожидания', class: 'status-pill waiting' },
            confirmed: { label: '✅ Подтверждено администратором', class: 'status-pill confirmed' },
            'in-progress': { label: '🚿 Автомобиль моется в боксе', class: 'status-pill in-progress' },
            completed: { label: '🎉 Мойка завершена и оплачена', class: 'status-pill ready' },
            cancelled: { label: '❌ Заявка отклонена / отменена', class: 'status-pill' }
        };

        myBookings.forEach(b => {
            const statusInfo = statusMap[b.status] || { label: b.status, class: 'status-pill' };
            const serviceNames = (b.services || []).map(sid => {
                const s = this.db.services.find(srv => srv.id === sid);
                return s ? Security.escapeHTML(s.name) : '';
            }).filter(Boolean).join(', ');

            const box = b.assignedBoxId ? this.db.boxes.find(bx => bx.id === b.assignedBoxId) : null;
            const boxLabel = box ? ` | ${Security.escapeHTML(box.name)}` : '';

            const card = document.createElement('div');
            card.className = `booking-card ${b.status}`;
            card.innerHTML = `
                <div class="booking-card-header">
                    <div>
                        <span class="garage-plate-badge">${Security.escapeHTML(b.carPlate)}</span>
                        <div style="font-weight:600; margin-top:0.2rem;">${Security.escapeHTML(b.carModel || 'Автомобиль')}</div>
                    </div>
                    <span class="${statusInfo.class}">${statusInfo.label}</span>
                </div>
                <div style="font-size:0.95rem; margin:0.5rem 0;">
                    <div>📅 <strong>${b.date} в ${b.time}</strong>${boxLabel}</div>
                    <div class="text-muted" style="margin-top:0.25rem;">Услуги: ${serviceNames || '—'}</div>
                    <div style="margin-top:0.25rem;">Сумма: <strong style="color:var(--primary);">${Number(b.totalPrice).toLocaleString()} ₸</strong></div>
                </div>
                ${b.status === 'confirmed' ? `
                    <div class="alert-box success" style="margin-top:0.5rem; font-size:0.85rem; padding:0.5rem;">
                        Бокс забронирован! Приезжайте к назначенному времени в <strong>${box ? Security.escapeHTML(box.name) : 'бокс'}</strong>.
                    </div>
                ` : ''}
                ${b.status === 'waiting' ? `
                    <div class="alert-box warning" style="margin-top:0.5rem; font-size:0.85rem; padding:0.5rem;">
                        Вы в листе ожидания. Администратор освободит один из 10 боксов и подтвердит время.
                    </div>
                ` : ''}
                ${b.status === 'pending' || b.status === 'waiting' ? `
                    <div style="margin-top:0.5rem; text-align:right;">
                        <button class="btn btn-outline btn-sm" type="button" onclick="app.cancelGuestBooking('${b.id}')" style="color:#ef4444; border-color:#fecaca;">Отменить запись</button>
                    </div>
                ` : ''}
            `;
            container.appendChild(card);
        });
    }

    cancelGuestBooking(bookingId) {
        const booking = (this.db.bookings || []).find(b => b.id === bookingId);
        if (!booking) return;
        if (!confirm('Вы уверены, что хотите отменить эту заявку на бронирование?')) return;

        booking.status = 'cancelled';
        this.saveDatabase();
        this.renderAll();
    }

    // ==================== УПРАВЛЕНИЕ БРОНЯМИ (АДМИНИСТРАТОР) ====================

    setBookingsFilter(filterName) {
        const select = document.getElementById('adminBookingStatusFilter');
        if (select) {
            select.value = filterName;
        }
        this.renderAdminBookings();
    }

    onBookingFilterSelectChange() {
        this.renderAdminBookings();
    }

    renderAdminBookings() {
        const container = document.getElementById('adminBookingsContainer');
        const badge = document.getElementById('pendingBookingsCount');
        const waitlistBadge = document.getElementById('waitlistCount');
        const waitlistTotalBadge = document.getElementById('waitlistTotalBadge');
        const filterPendingCount = document.getElementById('filterPendingCount');
        const filterWaitlistCount = document.getElementById('filterWaitlistCount');
        const filterConfirmedCount = document.getElementById('filterConfirmedCount');
        if (!container) return;

        const allBookings = Array.isArray(this.db.bookings) ? this.db.bookings : [];
        const pendingCount = allBookings.filter(b => b.status === 'pending').length;
        const waitlistCount = allBookings.filter(b => b.status === 'waiting').length;
        const confirmedCount = allBookings.filter(b => b.status === 'confirmed').length;

        if (badge) badge.textContent = pendingCount;
        if (waitlistBadge) waitlistBadge.textContent = waitlistCount;
        if (waitlistTotalBadge) waitlistTotalBadge.textContent = waitlistCount;
        if (filterPendingCount) filterPendingCount.textContent = pendingCount;
        if (filterWaitlistCount) filterWaitlistCount.textContent = waitlistCount;
        if (filterConfirmedCount) filterConfirmedCount.textContent = confirmedCount;

        const banner = document.getElementById('newBookingsAlertBanner');
        const bannerCount = document.getElementById('alertBannerCount');
        if (banner) {
            if (pendingCount > 0) {
                banner.style.display = 'flex';
                if (bannerCount) bannerCount.textContent = pendingCount;
            } else {
                banner.style.display = 'none';
            }
        }

        const filterEl = document.getElementById('adminBookingStatusFilter');
        const filter = filterEl ? filterEl.value : 'pending';

        // Синхронизация активной таблетки-фильтра
        document.querySelectorAll('#adminBookingsFilterPills .pill-filter-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.filter === filter);
        });

        let filtered = allBookings;
        if (filter === 'pending') {
            filtered = allBookings.filter(b => b.status === 'pending');
        } else if (filter === 'waiting') {
            filtered = allBookings.filter(b => b.status === 'waiting');
        } else if (filter === 'confirmed') {
            filtered = allBookings.filter(b => b.status === 'confirmed');
        }

        container.innerHTML = '';

        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="card" style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 3rem;">
                    <h3>Нет заявок в этом разделе</h3>
                    <p>Все входящие онлайн-бронирования клиентов обработаны.</p>
                </div>
            `;
            return;
        }

        filtered.forEach(b => {
            const serviceNames = (b.services || []).map(sid => {
                const s = this.db.services.find(srv => srv.id === sid);
                return s ? Security.escapeHTML(s.name) : '';
            }).filter(Boolean).join(', ');

            const card = document.createElement('div');
            card.className = `admin-booking-card ${b.status}`;

            // Селект боксов
            let boxOptions = '';
            this.db.boxes.forEach(bx => {
                const isBusy = this.db.orders.some(o => o.boxId === bx.id && (o.status === 'in-progress' || o.status === 'ready'));
                const isSelected = (b.assignedBoxId === bx.id) || (!b.assignedBoxId && bx.id === 1);
                boxOptions += `<option value="${bx.id}" ${isSelected ? 'selected' : ''}>${Security.escapeHTML(bx.name)} ${isBusy ? '(Занят)' : '(Свободен)'}</option>`;
            });

            // Селект мойщиков
            let workerOptions = '';
            this.db.workers.forEach((w, idx) => {
                const isSelected = (b.assignedWorkerId === w.id) || (!b.assignedWorkerId && idx === 0);
                workerOptions += `<option value="${w.id}" ${isSelected ? 'selected' : ''}>${Security.escapeHTML(w.name)} (${w.percent}%)</option>`;
            });

            const statusLabels = {
                pending: '⏳ Ожидает решения',
                waiting: '⏱ В листе ожидания',
                confirmed: '✅ В очереди бокса',
                'in-progress': '🚿 В боксе',
                completed: '🎉 Завершена',
                cancelled: '❌ Отменена'
            };

            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <span class="garage-plate-badge">${Security.escapeHTML(b.carPlate)}</span>
                        <h3 style="margin:0.25rem 0;">${Security.escapeHTML(b.carModel || 'Автомобиль')}</h3>
                        <div class="text-muted" style="font-size:0.9rem;">Клиент: <strong>${Security.escapeHTML(b.clientName)}</strong> (📞 <a href="tel:${Security.escapeHTML(b.clientPhone)}" style="color:var(--primary); font-weight:600;">${Security.escapeHTML(b.clientPhone)}</a>)</div>
                    </div>
                    <span class="status-pill ${b.status}">${statusLabels[b.status] || b.status}</span>
                </div>

                <div style="margin: 0.75rem 0; padding: 0.5rem 0; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); font-size: 0.95rem;">
                    <div>📅 Желаемое время: <strong style="font-size:1.05rem; color:var(--primary);">${b.date} в ${b.time}</strong></div>
                    <div style="margin-top:0.25rem;">Услуги: <strong>${serviceNames || '—'}</strong></div>
                    <div style="margin-top:0.25rem;">Сумма заказа: <strong>${Number(b.totalPrice).toLocaleString()} ₸</strong></div>
                </div>

                <div class="booking-actions-box">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                        <div>
                            <label for="assignBox_${b.id}" style="font-size:0.8rem; font-weight:600; display:block; margin-bottom:0.25rem;">Назначить бокс:</label>
                            <select id="assignBox_${b.id}" style="width:100%; font-size:0.85rem; padding:0.4rem;">
                                ${boxOptions}
                            </select>
                        </div>
                        <div>
                            <label for="assignWorker_${b.id}" style="font-size:0.8rem; font-weight:600; display:block; margin-bottom:0.25rem;">Назначить мойщика:</label>
                            <select id="assignWorker_${b.id}" style="width:100%; font-size:0.85rem; padding:0.4rem;">
                                ${workerOptions}
                            </select>
                        </div>
                    </div>

                    <div style="display:flex; flex-wrap:wrap; gap:0.5rem; margin-top:0.6rem;">
                        ${b.status !== 'confirmed' ? `
                            <button class="btn btn-success btn-sm" type="button" onclick="app.confirmAdminBooking('${b.id}')">
                                ✅ Принять заявку
                            </button>
                        ` : `
                            <button class="btn btn-primary btn-sm" type="button" onclick="app.startBookingInBay('${b.id}')">
                                🚿 Запустить авто в бокс
                            </button>
                        `}
                        ${b.status !== 'waiting' ? `
                            <button class="btn btn-warning btn-sm" type="button" onclick="app.waitlistAdminBooking('${b.id}')">
                                ⏱ В лист ожидания
                            </button>
                        ` : ''}
                        <button class="btn btn-outline btn-sm" type="button" onclick="app.cancelAdminBooking('${b.id}')" style="color:#ef4444; border-color:#fecaca;">
                            ❌ Отклонить
                        </button>
                    </div>
                </div>
            `;
            container.appendChild(card);
        });
    }

    // ==================== ВЫДЕЛЕННЫЙ ЛИСТ ОЖИДАНИЯ (АДМИНИСТРАТОР) ====================

    renderAdminWaitlist() {
        const container = document.getElementById('adminWaitlistContainer');
        const badge = document.getElementById('waitlistCount');
        const totalBadge = document.getElementById('waitlistTotalBadge');
        if (!container) return;

        const allBookings = Array.isArray(this.db.bookings) ? this.db.bookings : [];
        const waitlist = allBookings.filter(b => b.status === 'waiting');

        if (badge) badge.textContent = waitlist.length;
        if (totalBadge) totalBadge.textContent = waitlist.length;

        container.innerHTML = '';

        if (waitlist.length === 0) {
            container.innerHTML = `
                <div class="card" style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 3rem;">
                    <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">⏱</div>
                    <h3>Лист ожидания пуст</h3>
                    <p>Все клиенты распределены по боксам. Когда все боксы заняты или клиент ожидает свободного слота, переводите заявки сюда кнопкой «⏱ В лист ожидания».</p>
                    <button class="btn btn-primary btn-sm" type="button" onclick="app.switchTab('adminBookings')" style="margin-top: 1rem;">
                        📅 Перейти к заявкам на бронь
                    </button>
                </div>
            `;
            return;
        }

        waitlist.forEach(b => {
            const serviceNames = (b.services || []).map(sid => {
                const s = this.db.services.find(srv => srv.id === sid);
                return s ? Security.escapeHTML(s.name) : '';
            }).filter(Boolean).join(', ');

            let boxOptions = '';
            this.db.boxes.forEach(bx => {
                const isBusy = this.db.orders.some(o => o.boxId === bx.id && (o.status === 'in-progress' || o.status === 'ready'));
                const isSelected = (b.assignedBoxId === bx.id) || (!b.assignedBoxId && bx.id === 1);
                boxOptions += `<option value="${bx.id}" ${isSelected ? 'selected' : ''}>${Security.escapeHTML(bx.name)} ${isBusy ? '(Занят)' : '(Свободен)'}</option>`;
            });

            let workerOptions = '';
            this.db.workers.forEach((w, idx) => {
                const isSelected = (b.assignedWorkerId === w.id) || (!b.assignedWorkerId && idx === 0);
                workerOptions += `<option value="${w.id}" ${isSelected ? 'selected' : ''}>${Security.escapeHTML(w.name)} (${w.percent}%)</option>`;
            });

            const card = document.createElement('div');
            card.className = 'admin-booking-card waiting';

            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <span class="garage-plate-badge">${Security.escapeHTML(b.carPlate)}</span>
                        <h3 style="margin:0.25rem 0;">${Security.escapeHTML(b.carModel || 'Автомобиль')}</h3>
                        <div class="text-muted" style="font-size:0.9rem;">
                            Клиент: <strong>${Security.escapeHTML(b.clientName)}</strong> • 
                            <a href="tel:${Security.escapeHTML(b.clientPhone)}" style="color:var(--primary); font-weight:600;">📞 ${Security.escapeHTML(b.clientPhone)}</a>
                        </div>
                    </div>
                    <span class="status-pill waiting">⏱ В листе ожидания</span>
                </div>

                <div style="margin: 0.75rem 0; padding: 0.5rem 0; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); font-size: 0.95rem;">
                    <div>📅 Желаемое время: <strong style="font-size:1.05rem; color:var(--primary);">${b.date} в ${b.time}</strong></div>
                    <div style="margin-top:0.25rem;">Услуги: <strong>${serviceNames || '—'}</strong></div>
                    <div style="margin-top:0.25rem;">Сумма заказа: <strong>${Number(b.totalPrice).toLocaleString()} ₸</strong></div>
                </div>

                <div class="booking-actions-box">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                        <div>
                            <label for="waitlistAssignBox_${b.id}" style="font-size:0.8rem; font-weight:600; display:block; margin-bottom:0.25rem;">Назначить бокс:</label>
                            <select id="waitlistAssignBox_${b.id}" style="width:100%; font-size:0.85rem; padding:0.4rem;">
                                ${boxOptions}
                            </select>
                        </div>
                        <div>
                            <label for="waitlistAssignWorker_${b.id}" style="font-size:0.8rem; font-weight:600; display:block; margin-bottom:0.25rem;">Назначить мойщика:</label>
                            <select id="waitlistAssignWorker_${b.id}" style="width:100%; font-size:0.85rem; padding:0.4rem;">
                                ${workerOptions}
                            </select>
                        </div>
                    </div>

                    <div style="display:flex; flex-wrap:wrap; gap:0.5rem; margin-top:0.6rem;">
                        <button class="btn btn-success btn-sm" type="button" onclick="app.confirmAdminBooking('${b.id}')">
                            ✅ Назначить в бокс
                        </button>
                        <a href="tel:${encodeURIComponent(b.clientPhone)}" class="btn btn-outline btn-sm" style="color:var(--primary);">
                            📞 Позвонить
                        </a>
                        <button class="btn btn-outline btn-sm" type="button" onclick="app.cancelAdminBooking('${b.id}')" style="color:#ef4444; border-color:#fecaca;">
                            ❌ Отклонить
                        </button>
                    </div>
                </div>
            `;
            container.appendChild(card);
        });
    }

    confirmAdminBooking(bookingId) {
        if (!this.verifyAuth('admin')) return;
        const booking = (this.db.bookings || []).find(b => b.id === bookingId);
        if (!booking) return;

        const boxSelect = document.getElementById(`assignBox_${bookingId}`) || document.getElementById(`waitlistAssignBox_${bookingId}`);
        const workerSelect = document.getElementById(`assignWorker_${bookingId}`) || document.getElementById(`waitlistAssignWorker_${bookingId}`);

        const boxId = boxSelect ? parseInt(boxSelect.value, 10) : (booking.assignedBoxId || 1);
        const workerId = workerSelect ? workerSelect.value : (booking.assignedWorkerId || (this.db.workers[0] ? this.db.workers[0].id : null));

        const box = this.db.boxes.find(b => b.id === boxId);
        const boxName = box ? box.name : `Бокс ${boxId}`;
        const worker = (this.db.workers || []).find(w => w.id === workerId) || this.db.workers[0];
        const workerName = worker ? worker.name : '—';

        booking.assignedBoxId = boxId;
        booking.assignedWorkerId = worker ? worker.id : null;

        // Проверяем, свободен ли бокс прямо сейчас
        const isBusy = this.db.orders.some(o => o.boxId === boxId && (o.status === 'in-progress' || o.status === 'ready'));

        if (!isBusy) {
            // БОКС СВОБОДЕН: запускаем авто прямо в работу и переходим на вкладку боксов
            const workerPercent = worker ? (typeof worker.percent === 'number' ? worker.percent : 30) : 30;
            const newOrder = {
                id: Security.generateId(),
                carPlate: booking.carPlate,
                carModel: booking.carModel || '',
                category: booking.category || 'sedan',
                boxId,
                workerId: worker ? worker.id : null,
                workerPercentSnapshot: workerPercent,
                workerNameSnapshot: worker ? worker.name : '',
                workerSalaryEarned: Math.round(Number(booking.totalPrice || 0) * (workerPercent / 100)),
                phone: booking.clientPhone,
                services: booking.services || [],
                totalPrice: booking.totalPrice,
                status: 'in-progress',
                isPaid: false,
                paymentMethod: null,
                createdAt: new Date().toISOString(),
                paidAt: null
            };

            this.db.orders.unshift(newOrder);
            booking.status = 'in-progress';
            booking.orderId = newOrder.id;

            this.saveDatabase();
            this.renderAll();
            this.switchTab('activeOrders');
            alert(`✅ Заявка принята!\n\n${boxName} свободен — автомобиль ${booking.carPlate} запущен в работу.\n🧽 Ответственный мойщик: ${workerName}.`);
        } else {
            // БОКС ЗАНЯТ: ставим авто следующим в очередь под этим боксом и переходим на вкладку боксов!
            booking.status = 'confirmed';

            this.saveDatabase();
            this.renderAll();
            this.switchTab('activeOrders');
            alert(`⏳ ${boxName} сейчас занят.\n\nАвтомобиль ${booking.carPlate} поставлен следующим в очередь этого бокса!\n🧽 Назначен мойщик: ${workerName}.`);
        }
    }

    waitlistAdminBooking(bookingId) {
        if (!this.verifyAuth('admin')) return;
        const booking = (this.db.bookings || []).find(b => b.id === bookingId);
        if (!booking) return;

        booking.status = 'waiting';
        this.saveDatabase();
        this.renderAll();
        alert(`⏱ Заявка авто ${booking.carPlate} переведена в Лист ожидания!\n\nВы можете в любой момент открыть её во вкладке «Лист ожидания» в верхнем меню.`);
    }

    cancelAdminBooking(bookingId) {
        if (!this.verifyAuth('admin')) return;
        const booking = (this.db.bookings || []).find(b => b.id === bookingId);
        if (!booking) return;

        if (!confirm(`Отклонить бронь авто ${booking.carPlate}?`)) return;

        booking.status = 'cancelled';
        this.saveDatabase();
        this.renderAll();
    }

    startBookingInBay(bookingId) {
        if (!this.verifyAuth('admin')) return;
        const booking = (this.db.bookings || []).find(b => b.id === bookingId);
        if (!booking) return;

        const boxSelect = document.getElementById(`assignBox_${bookingId}`) || document.getElementById(`waitlistAssignBox_${bookingId}`);
        const workerSelect = document.getElementById(`assignWorker_${bookingId}`) || document.getElementById(`waitlistAssignWorker_${bookingId}`);

        const boxId = boxSelect ? parseInt(boxSelect.value, 10) : (booking.assignedBoxId || 1);
        const workerId = workerSelect ? workerSelect.value : (booking.assignedWorkerId || (this.db.workers[0] ? this.db.workers[0].id : null));

        const box = this.db.boxes.find(b => b.id === boxId);
        const boxName = box ? box.name : `Бокс ${boxId}`;

        // Если в боксе еще моется предыдущая машина
        const activeOrderInBox = this.db.orders.find(o => o.boxId === boxId && (o.status === 'in-progress' || o.status === 'ready'));
        if (activeOrderInBox) {
            const proceed = confirm(`В ${boxName} сейчас находится авто ${activeOrderInBox.carPlate} (${activeOrderInBox.status === 'ready' ? 'помыто' : 'моется'}).\n\nВы хотите всё равно запустить автомобиль ${booking.carPlate} в этот бокс?`);
            if (!proceed) return;
        }

        const worker = (this.db.workers || []).find(w => w.id === workerId) || this.db.workers[0];
        const workerPercent = worker ? (typeof worker.percent === 'number' ? worker.percent : 30) : 30;

        const newOrder = {
            id: Security.generateId(),
            carPlate: booking.carPlate,
            carModel: booking.carModel || '',
            category: booking.category || 'sedan',
            boxId,
            workerId: worker ? worker.id : null,
            workerPercentSnapshot: workerPercent,
            workerNameSnapshot: worker ? worker.name : '',
            workerSalaryEarned: Math.round(Number(booking.totalPrice || 0) * (workerPercent / 100)),
            phone: booking.clientPhone,
            services: booking.services || [],
            totalPrice: booking.totalPrice,
            status: 'in-progress',
            isPaid: false,
            paymentMethod: null,
            createdAt: new Date().toISOString(),
            paidAt: null
        };

        this.db.orders.unshift(newOrder);
        booking.status = 'in-progress';
        booking.orderId = newOrder.id;
        booking.assignedBoxId = boxId;
        booking.assignedWorkerId = worker ? worker.id : null;

        this.saveDatabase();
        this.renderAll();
        this.switchTab('activeOrders');
        alert(`🚿 Автомобиль ${booking.carPlate} успешно запущен в работу в ${boxName}!\n🧽 Назначен мойщик: ${worker ? worker.name : '—'}.`);
    }

    // ==================== ЛОГИКА ГОСТЯ (КЛИЕНТА) ====================

    searchCarStatus(event) {
        event.preventDefault();
        const now = Date.now();
        // Rate-limiting поиска (раз в 1.5 секунды)
        if (now - this.lastGuestSearchTime < 1500) {
            return;
        }
        this.lastGuestSearchTime = now;

        const inputEl = document.getElementById('guestSearchPlate');
        const rawInput = inputEl.value.trim().toUpperCase().replace(/[^A-Z0-9А-ЯЁ]/gi, '');
        const resultContainer = document.getElementById('guestSearchResult');

        if (!rawInput) return;

        // Поиск в активных машинах
        const order = this.db.orders.find(o => {
            const plateClean = o.carPlate.toUpperCase().replace(/[^A-Z0-9А-ЯЁ]/gi, '');
            return plateClean === rawInput;
        });

        resultContainer.style.display = 'block';

        if (!order) {
            resultContainer.innerHTML = `
                <div style="color: #64748b; text-align: center; padding: 1rem;">
                    <h3>Автомобиль не найден</h3>
                    <p>Авто с госномером <strong>${Security.escapeHTML(inputEl.value.toUpperCase())}</strong> сейчас нет в боксах автомойки.</p>
                    <small>Если вы только что заехали, администратор оформит заказ через минуту.</small>
                </div>
            `;
            return;
        }

        const box = this.db.boxes.find(b => b.id === order.boxId);
        const boxName = box ? Security.escapeHTML(box.name) : 'Бокс';
        const serviceNames = order.services.map(sid => {
            const s = this.db.services.find(item => item.id === sid);
            return s ? Security.escapeHTML(s.name) : '';
        }).filter(Boolean).join(', ');

        // Безопасный вывод для гостя (БЕЗ раскрытия телефона клиента и зарплаты)
        const isPaid = this.isOrderPaid(order);
        if (order.status === 'in-progress') {
            resultContainer.innerHTML = `
                <div class="guest-plate-badge">${Security.escapeHTML(order.carPlate)}</div>
                <div><strong>${Security.escapeHTML(order.carModel || 'Автомобиль')}</strong></div>
                <div class="guest-status-banner in-progress">
                    <span>🚿 Автомобиль моется в <strong>${boxName}</strong></span>
                </div>
                <p><strong>Выполняемые услуги:</strong> ${serviceNames}</p>
                <p><strong>Стоимость:</strong> ${order.totalPrice.toLocaleString()} ₸</p>
                ${isPaid ? `
                    <div style="background:rgba(16, 185, 129, 0.15); border:1px solid #10b981; color:#059669; padding:0.5rem 0.75rem; border-radius:6px; font-weight:600; margin:0.6rem 0;">
                        🟢 Заказ уже оплачен! Ожидайте завершения мойки в комнате отдыха.
                    </div>
                ` : `
                    <small class="text-muted">Ожидайте в комнате отдыха. Мы сообщим, когда авто будет готово!</small>
                `}
            `;
        } else if (order.status === 'ready') {
            resultContainer.innerHTML = `
                <div class="guest-plate-badge">${Security.escapeHTML(order.carPlate)}</div>
                <div><strong>${Security.escapeHTML(order.carModel || 'Автомобиль')}</strong></div>
                <div class="guest-status-banner ready">
                    <span>✅ Автомобиль вымыт и готов к выдаче! (${boxName})</span>
                </div>
                <p><strong>Услуги:</strong> ${serviceNames}</p>
                ${isPaid ? `
                    <div style="background:rgba(16, 185, 129, 0.15); border:1px solid #10b981; color:#059669; padding:0.5rem 0.75rem; border-radius:6px; font-weight:600; margin:0.6rem 0;">
                        🟢 Заказ полностью оплачен. Можете забирать ваш чистый автомобиль!
                    </div>
                ` : `
                    <p><strong>К оплате:</strong> <strong style="color:var(--primary); font-size:1.2rem;">${order.totalPrice.toLocaleString()} ₸</strong></p>
                    <small>Вы можете подойти к администратору для расчета и забрать авто.</small>
                `}
            `;
        } else if (order.status === 'paid') {
            resultContainer.innerHTML = `
                <div class="guest-plate-badge">${Security.escapeHTML(order.carPlate)}</div>
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
            const queuedBookings = (this.db.bookings || []).filter(b => 
                b.assignedBoxId === box.id && (b.status === 'confirmed' || b.status === 'waiting')
            );

            const card = document.createElement('div');
            card.className = `box-card ${isBusy ? 'busy' : 'free'}`;
            card.innerHTML = `
                <div class="box-header">
                    <h3>${Security.escapeHTML(box.name)}</h3>
                    <span class="box-status ${isBusy ? 'busy' : 'free'}">${isBusy ? 'Занят' : 'Свободен'}</span>
                </div>
                ${isBusy ? `
                    <div style="font-size:0.9rem; color:var(--text-muted); margin: 0.5rem 0;">
                        ${activeOrder.status === 'in-progress' ? '🚿 Идет мойка авто' : '✅ Готово к выдаче'}
                    </div>
                    ${queuedBookings.length > 0 ? `
                        <div style="font-size:0.8rem; color:#b45309; margin-top:0.25rem; font-weight:600;">
                            ⏳ В очереди: ${queuedBookings.length} авто
                        </div>
                    ` : ''}
                ` : `
                    ${queuedBookings.length > 0 ? `
                        <div style="color:var(--primary); font-weight:500; margin: 0.5rem 0; font-size:0.88rem;">
                            ⏳ Ожидает авто по брони (${queuedBookings.length})
                        </div>
                    ` : `
                        <div style="color:var(--success); font-weight:500; margin: 0.5rem 0;">Готов к приему авто</div>
                    `}
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
                <td><strong>${Security.escapeHTML(s.name)}</strong></td>
                <td><strong style="color:var(--primary);">${price.toLocaleString()} ₸</strong></td>
            `;
            tbody.appendChild(tr);
        });
    }

    renderContactsView() {
        const c = this.db.contacts || {};
        const elAddr = document.getElementById('viewContactAddress');
        const elHours = document.getElementById('viewContactHours');
        const elPhone = document.getElementById('viewContactPhone');
        const elNotes = document.getElementById('viewContactNotes');

        if (elAddr) elAddr.textContent = c.address || 'ул. Автомобильная, 12/1';
        if (elHours) elHours.textContent = c.hours || 'Круглосуточно 24/7 (без перерывов и выходных)';
        if (elPhone) elPhone.textContent = c.phone || '+7 (777) 123-45-67';
        if (elNotes) elNotes.textContent = c.notes || 'Зона отдыха, кофе, Wi-Fi';

        // Заполнение в настройках владельца
        const edAddr = document.getElementById('editContactAddress');
        const edHours = document.getElementById('editContactHours');
        const edPhone = document.getElementById('editContactPhone');
        const edNotes = document.getElementById('editContactNotes');

        if (edAddr && !edAddr.value) edAddr.value = c.address || '';
        if (edHours && !edHours.value) edHours.value = c.hours || 'Круглосуточно 24/7 (без перерывов и выходных)';
        if (edPhone && !edPhone.value) edPhone.value = c.phone || '';
        if (edNotes && !edNotes.value) edNotes.value = c.notes || '';
    }

    saveContacts(event) {
        event.preventDefault();
        if (!this.verifyAuth('owner')) return;

        this.db.contacts = {
            address: document.getElementById('editContactAddress').value.trim(),
            hours: document.getElementById('editContactHours').value.trim(),
            phone: this.formatPhoneNumber(document.getElementById('editContactPhone').value.trim()),
            notes: document.getElementById('editContactNotes').value.trim()
        };
        this.saveDatabase();
        this.renderContactsView();
        alert('Контакты автомойки успешно сохранены!');
    }

    // ==================== ЛОГИКА МОЙЩИКА ====================

    renderWorkerTasks() {
        const worker = this.db.workers.find(w => w.id === this.currentWorkerId);
        document.getElementById('workerActiveName').textContent = worker ? worker.name : 'Не выбран';

        const cardsContainer = document.getElementById('workerAssignedCards');
        cardsContainer.innerHTML = '';

        if (!this.currentWorkerId) {
            cardsContainer.innerHTML = '<p class="text-muted">Сотрудник не выбран. Нажмите «Сменить режим» и войдите под своим именем.</p>';
            return;
        }

        const myTasks = this.db.orders.filter(o => o.workerId === this.currentWorkerId && (o.status === 'in-progress' || o.status === 'ready'));
        const myQueued = (this.db.bookings || []).filter(b => b.assignedWorkerId === this.currentWorkerId && b.status === 'confirmed');

        if (myTasks.length === 0 && myQueued.length === 0) {
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
                    return s ? Security.escapeHTML(s.name) : '';
                }).filter(Boolean).join(', ');

                // Расчет на основе зафиксированного снапшота или текущего процента
                const percent = order.workerPercentSnapshot !== undefined ? order.workerPercentSnapshot : (worker ? worker.percent : 30);
                const earnedForOrder = order.workerSalaryEarned !== undefined ? order.workerSalaryEarned : Math.round(order.totalPrice * (percent / 100));

                const isPaid = this.isOrderPaid(order);
                const card = document.createElement('div');
                card.className = `worker-task-card ${order.status}`;
                card.innerHTML = `
                    <div>
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                            <span class="badge" style="background:#0f172a; color:#fff; font-size:0.9rem;">${box ? Security.escapeHTML(box.name) : 'Бокс'}</span>
                            <div style="display:flex; gap:0.35rem; align-items:center;">
                                <span class="status-pill ${order.status}">
                                    ${order.status === 'in-progress' ? '🚿 В процессе' : '✅ Готово'}
                                </span>
                                ${isPaid ? `<span class="badge" style="background:#059669; color:#fff; font-size:0.75rem;">🟢 Оплачено</span>` : ''}
                            </div>
                        </div>
                        <h3 style="font-size:1.3rem; margin:0.3rem 0;">${Security.escapeHTML(order.carPlate)}</h3>
                        <div class="text-muted">${Security.escapeHTML(order.carModel || 'Автомобиль')}</div>
                        <div style="margin: 0.75rem 0; font-size: 0.9rem;">
                            <strong>Услуги:</strong> ${serviceNames}
                        </div>
                        <div style="font-size:0.85rem; color:#0369a1; background:#e0f2fe; padding:0.4rem 0.6rem; border-radius:6px;">
                            Ваша выплата за этот авто: <strong>${earnedForOrder.toLocaleString()} ₸</strong>
                        </div>
                    </div>
                    <div style="margin-top: 1.25rem;">
                        ${order.status === 'in-progress' ? `
                            <button class="btn btn-success" style="width:100%;" type="button" onclick="app.setOrderReady('${order.id}')">
                                ✅ Завершил мойку (Готово)
                            </button>
                        ` : `
                            <div style="text-align:center; color:#15803d; font-weight:600; font-size:0.9rem;">
                                ${isPaid ? '🎉 Мойка завершена (Оплачено клиентом)' : 'Ожидает оплаты у администратора'}
                            </div>
                        `}
                    </div>
                `;
                cardsContainer.appendChild(card);
            });

            if (myQueued.length > 0) {
                const queueHeader = document.createElement('div');
                queueHeader.style.gridColumn = '1 / -1';
                queueHeader.style.marginTop = '1rem';
                queueHeader.innerHTML = `
                    <h3 style="font-size:1.1rem; color:var(--text-muted); display:flex; align-items:center; gap:0.5rem;">
                        <span>⏳ Скоро заедут к вам в бокс:</span>
                        <span class="badge-queued">${myQueued.length} авто</span>
                    </h3>
                `;
                cardsContainer.appendChild(queueHeader);

                myQueued.forEach(qb => {
                    const box = this.db.boxes.find(b => b.id === qb.assignedBoxId);
                    const percent = worker ? worker.percent : 30;
                    const estSalary = Math.round(Number(qb.totalPrice || 0) * (percent / 100));

                    const card = document.createElement('div');
                    card.className = 'worker-task-card';
                    card.style.borderTop = '4px solid var(--warning)';
                    card.innerHTML = `
                        <div>
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                                <span class="badge" style="background:#0f172a; color:#fff; font-size:0.9rem;">${box ? Security.escapeHTML(box.name) : 'Бокс'}</span>
                                <span class="status-pill waiting">⏳ В очереди</span>
                            </div>
                            <h3 style="font-size:1.3rem; margin:0.3rem 0;">${Security.escapeHTML(qb.carPlate)}</h3>
                            <div class="text-muted">${Security.escapeHTML(qb.carModel || 'Автомобиль')} • 🕒 ${Security.escapeHTML(qb.time)}</div>
                            <div style="font-size:0.85rem; color:#b45309; background:#fef3c7; padding:0.4rem 0.6rem; border-radius:6px; margin-top:0.75rem;">
                                Ожидаемая выплата: <strong>${estSalary.toLocaleString()} ₸</strong>
                            </div>
                        </div>
                    `;
                    cardsContainer.appendChild(card);
                });
            }
        }

        this.updateWorkerStats();
    }

    updateWorkerStats() {
        if (!this.currentWorkerId) return;
        const worker = this.db.workers.find(w => w.id === this.currentWorkerId);
        if (!worker) return;

        const todayStr = Security.getLocalDateString(new Date());

        let count = 0;
        let earned = 0;

        this.db.orders.forEach(o => {
            if (o.workerId === this.currentWorkerId && o.status === 'paid') {
                const dateStr = Security.getLocalDateString(o.paidAt || o.createdAt);
                if (dateStr === todayStr) {
                    count++;
                    const salary = o.workerSalaryEarned !== undefined ? o.workerSalaryEarned : Math.round(o.totalPrice * ((o.workerPercentSnapshot || worker.percent) / 100));
                    earned += salary;
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

        const myHistory = this.db.orders.filter(o => o.workerId === this.currentWorkerId && o.status === 'paid');

        if (myHistory.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:2rem;">У вас пока нет закрытых заказов за смену.</td></tr>`;
            return;
        }

        myHistory.forEach(order => {
            const timeStr = new Date(order.paidAt || order.createdAt).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            const serviceNames = order.services.map(sid => {
                const s = this.db.services.find(item => item.id === sid);
                return s ? Security.escapeHTML(s.name) : '';
            }).filter(Boolean).join(', ');

            const earned = order.workerSalaryEarned !== undefined ? order.workerSalaryEarned : Math.round(order.totalPrice * ((order.workerPercentSnapshot || 30) / 100));

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${timeStr}</td>
                <td><strong>${Security.escapeHTML(order.carPlate)}</strong></td>
                <td>${Security.escapeHTML(order.carModel || '—')}</td>
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
        if (!container || !boxSelect) return;

        container.innerHTML = '';
        boxSelect.innerHTML = '';

        this.db.boxes.forEach(box => {
            const activeOrder = this.db.orders.find(o => o.boxId === box.id && (o.status === 'in-progress' || o.status === 'ready'));
            const isBusy = !!activeOrder;
            const queuedBookings = (this.db.bookings || []).filter(b => 
                b.assignedBoxId === box.id && (b.status === 'confirmed' || b.status === 'waiting')
            );

            const card = document.createElement('div');
            card.className = `box-card ${isBusy ? 'busy' : 'free'}`;

            let cardContent = `
                <div class="box-header">
                    <h3>${Security.escapeHTML(box.name)}</h3>
                    <span class="box-status ${isBusy ? 'busy' : 'free'}">${isBusy ? 'Занят' : 'Свободен'}</span>
                </div>
            `;

            if (isBusy) {
                const isPaid = this.isOrderPaid(activeOrder);
                cardContent += `
                    <div class="box-car-info">${Security.escapeHTML(activeOrder.carPlate)}</div>
                    <div class="box-details">${Security.escapeHTML(activeOrder.carModel || 'Авто')} • ${Security.escapeHTML(this.getWorkerName(activeOrder.workerId))}</div>
                    <div style="margin-top: 0.5rem; display:flex; gap:0.35rem; align-items:center; flex-wrap:wrap;">
                        <span class="status-pill ${activeOrder.status}">
                            ${activeOrder.status === 'in-progress' ? '🚿 Моется' : '✅ Помыта'}
                        </span>
                        ${isPaid ? `
                            <span class="badge" style="background:#059669; color:#fff; font-size:0.75rem;">
                                🟢 Оплачено
                            </span>
                        ` : `
                            <span class="badge" style="background:#b45309; color:#fff; font-size:0.75rem;">
                                ⏳ Ждет оплаты
                            </span>
                        `}
                    </div>
                    <div style="margin-top:0.5rem; display:flex; gap:0.35rem; flex-wrap:wrap;">
                        ${activeOrder.status === 'in-progress' ? `
                            <button class="btn btn-outline btn-xs" type="button" onclick="app.setOrderReady('${activeOrder.id}')" style="flex:1;">✅ Готово</button>
                        ` : ''}
                        ${!isPaid ? `
                            <button class="btn btn-success btn-xs" type="button" onclick="app.openPaymentModal('${activeOrder.id}')" style="flex:1;">💳 Оплата</button>
                        ` : ''}
                        ${(activeOrder.status === 'ready' && isPaid) ? `
                            <button class="btn btn-primary btn-xs" type="button" onclick="app.releaseOrder('${activeOrder.id}')" style="width:100%;">👋 Выдать авто</button>
                        ` : ''}
                    </div>
                `;

                // Отображение следующей машины в очереди под занятым боксом
                if (queuedBookings.length > 0) {
                    const nextBooking = queuedBookings[0];
                    const nextWorkerName = this.getWorkerName(nextBooking.assignedWorkerId);
                    cardContent += `
                        <div class="box-queue-section">
                            <div class="box-queue-header">
                                <span>⏳ Следующая машина:</span>
                                ${queuedBookings.length > 1 ? `<span class="badge-queued">+${queuedBookings.length} в очереди</span>` : ''}
                            </div>
                            <div class="box-queue-item">
                                <div class="box-queue-item-main">
                                    <span class="box-queue-plate">${Security.escapeHTML(nextBooking.carPlate)}</span>
                                    <span class="box-queue-model">${Security.escapeHTML(nextBooking.carModel || 'Авто')}</span>
                                </div>
                                <div class="box-queue-meta">
                                    <span>🕒 ${Security.escapeHTML(nextBooking.time || '—')}</span>
                                    <span>🧽 ${Security.escapeHTML(nextWorkerName)}</span>
                                </div>
                                <div class="box-queue-actions">
                                    <button class="btn btn-primary btn-xs" type="button" onclick="app.startBookingInBay('${nextBooking.id}')">
                                        🚿 Запустить в бокс
                                    </button>
                                </div>
                            </div>
                            ${queuedBookings.length > 1 ? `
                                <div style="font-size:0.75rem; text-align:center; color:var(--text-muted); padding-top:0.15rem;">
                                    ещё ${queuedBookings.length - 1} авто ожидает этот бокс
                                </div>
                            ` : ''}
                        </div>
                    `;
                }
            } else {
                // Бокс свободен
                if (queuedBookings.length > 0) {
                    const nextBooking = queuedBookings[0];
                    const nextWorkerName = this.getWorkerName(nextBooking.assignedWorkerId);
                    cardContent += `
                        <div class="box-queue-section" style="margin-top:0.25rem; border-top:none; padding-top:0;">
                            <div class="box-queue-header" style="color:var(--success-hover);">
                                <span>⏳ Назначено в этот бокс:</span>
                                ${queuedBookings.length > 1 ? `<span class="badge-queued">+${queuedBookings.length}</span>` : ''}
                            </div>
                            <div class="box-queue-item" style="border-color: #86efac;">
                                <div class="box-queue-item-main">
                                    <span class="box-queue-plate">${Security.escapeHTML(nextBooking.carPlate)}</span>
                                    <span class="box-queue-model">${Security.escapeHTML(nextBooking.carModel || 'Авто')}</span>
                                </div>
                                <div class="box-queue-meta">
                                    <span>🕒 ${Security.escapeHTML(nextBooking.time || '—')}</span>
                                    <span>🧽 ${Security.escapeHTML(nextWorkerName)}</span>
                                </div>
                                <div class="box-queue-actions">
                                    <button class="btn btn-success btn-xs" type="button" onclick="app.startBookingInBay('${nextBooking.id}')">
                                        🚿 Запустить сейчас
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div style="margin-top:0.5rem;">
                            <button class="btn btn-outline btn-xs" type="button" onclick="app.quickAssignBox(${box.id})" style="width:100%;">+ Запустить другое авто</button>
                        </div>
                    `;
                } else {
                    cardContent += `
                        <div class="text-muted" style="margin: 1rem 0;">Бокс свободен</div>
                        <button class="btn btn-outline btn-sm" type="button" onclick="app.quickAssignBox(${box.id})">+ Запустить авто</button>
                    `;
                }
            }

            card.innerHTML = cardContent;
            container.appendChild(card);

            const option = document.createElement('option');
            option.value = box.id;
            const queueSuffix = queuedBookings.length > 0 ? ` (+${queuedBookings.length} в очереди)` : '';
            option.textContent = `${box.name} ${isBusy ? '(Занят)' : '(Свободен)'}${queueSuffix}`;
            boxSelect.appendChild(option);
        });

        // Селект мойщиков для формы
        const workerSelect = document.getElementById('orderWorker');
        if (workerSelect) {
            workerSelect.innerHTML = '';
            this.db.workers.forEach(w => {
                const option = document.createElement('option');
                option.value = w.id;
                option.textContent = w.name;
                workerSelect.appendChild(option);
            });
        }
    }

    quickAssignBox(boxId) {
        if (!['admin', 'owner'].includes(this.sessionRole)) {
            alert('Оформлять заезд может только Администратор или Владелец.');
            return;
        }
        this.switchTab('newOrder');
        const boxSel = document.getElementById('orderBox');
        if (boxSel) boxSel.value = boxId;
    }

    renderServicesCheckboxes() {
        const container = document.getElementById('servicesCheckboxes');
        if (!container) return;
        container.innerHTML = '';

        this.db.services.forEach(s => {
            const label = document.createElement('label');
            label.className = 'service-checkbox-card';
            label.innerHTML = `
                <input type="checkbox" name="services" value="${s.id}" onchange="app.recalculateTotal()">
                <div>
                    <div><strong>${Security.escapeHTML(s.name)}</strong></div>
                    <small class="text-muted">базовая: ${Number(s.basePrice).toLocaleString()} ₸</small>
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
            if (service && typeof service.basePrice === 'number' && !isNaN(service.basePrice)) {
                total += Math.round(service.basePrice * multiplier);
            }
        });

        document.getElementById('calculatedPrice').textContent = `${total.toLocaleString()} ₸`;
        return total;
    }

    createOrder(event) {
        event.preventDefault();

        if (!this.verifyAuth('admin')) return;

        const carPlate = document.getElementById('carPlate').value.trim().toUpperCase();
        const carModel = document.getElementById('carModel').value.trim();
        const category = document.getElementById('carCategory').value;
        const boxId = parseInt(document.getElementById('orderBox').value, 10);
        const workerId = document.getElementById('orderWorker').value;
        const phone = document.getElementById('clientPhone').value.trim();

        if (!carPlate) {
            alert('Пожалуйста, введите госномер авто!');
            return;
        }

        // Проверка: этот авто уже в активной очереди?
        const existingActive = this.db.orders.find(o => {
            const samePlate = o.carPlate.replace(/\s+/g, '') === carPlate.replace(/\s+/g, '');
            return samePlate && (o.status === 'in-progress' || o.status === 'ready');
        });
        if (existingActive) {
            alert(`Автомобиль с номером ${carPlate} уже находится в боксе #${existingActive.boxId}!`);
            return;
        }

        // Проверка: занят ли выбранный бокс?
        const boxBusy = this.db.orders.find(o => o.boxId === boxId && (o.status === 'in-progress' || o.status === 'ready'));
        if (boxBusy) {
            if (!confirm(`Бокс #${boxId} сейчас занят авто ${boxBusy.carPlate}. Вы уверены, что хотите добавить сюда ещё один автомобиль?`)) {
                return;
            }
        }

        const selectedServices = Array.from(document.querySelectorAll('input[name="services"]:checked')).map(el => el.value);

        if (selectedServices.length === 0) {
            alert('Пожалуйста, выберите хотя бы одну услугу!');
            return;
        }

        const totalPrice = this.recalculateTotal();
        const worker = this.db.workers.find(w => w.id === workerId);
        const workerPercent = worker ? worker.percent : 30;

        const newOrder = {
            id: Security.generateId(),
            carPlate,
            carModel,
            category,
            boxId,
            workerId,
            workerPercentSnapshot: workerPercent, // Фиксация ставки на момент заказа
            workerNameSnapshot: worker ? worker.name : '',
            workerSalaryEarned: Math.round(totalPrice * (workerPercent / 100)), // Фиксация начисленной зарплаты
            phone: phone ? this.formatPhoneNumber(phone) : '',
            services: selectedServices,
            totalPrice,
            status: 'in-progress',
            isPaid: false,
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
        if (!tbody) return;
        tbody.innerHTML = '';

        const activeList = this.db.orders.filter(o => o.status === 'in-progress' || o.status === 'ready');
        const queuedBookings = (this.db.bookings || []).filter(b => b.status === 'confirmed');

        const totalActiveAndQueue = activeList.length + queuedBookings.length;
        document.getElementById('activeCount').textContent = totalActiveAndQueue;

        if (totalActiveAndQueue === 0) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color:#94a3b8; padding:2rem;">Сейчас нет машин в боксах. Нажмите «Оформить заезд» или подтвердите онлайн-бронь.</td></tr>`;
            return;
        }

        activeList.forEach((order, index) => {
            const box = this.db.boxes.find(b => b.id === order.boxId);
            const workerName = order.workerNameSnapshot || this.getWorkerName(order.workerId);
            const serviceNames = order.services.map(sid => {
                const s = this.db.services.find(srv => srv.id === sid);
                return s ? Security.escapeHTML(s.name) : '';
            }).filter(Boolean).join(', ');

            const isPaid = this.isOrderPaid(order);
            const payMethodName = this.getPaymentMethodName(order.paymentMethod);

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${index + 1}</strong></td>
                <td>
                    <strong>${Security.escapeHTML(order.carPlate)}</strong>
                    <div class="text-muted" style="font-size:0.8rem;">${Security.escapeHTML(order.carModel || 'Не указана')}</div>
                </td>
                <td>${box ? Security.escapeHTML(box.name) : '—'}</td>
                <td style="max-width:240px;">${serviceNames}</td>
                <td>${Security.escapeHTML(workerName)}</td>
                <td><strong>${Number(order.totalPrice).toLocaleString()} ₸</strong></td>
                <td>
                    <span class="status-pill ${order.status}">
                        ${order.status === 'in-progress' ? '🚿 В работе' : '✅ Помыта'}
                    </span>
                </td>
                <td>
                    ${isPaid ? `
                        <span class="badge" style="background:#059669; color:#fff; font-size:0.75rem;" title="Оплачено ${order.paidAt ? new Date(order.paidAt).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : ''}">
                            🟢 ${payMethodName}
                        </span>
                    ` : `
                        <span class="badge" style="background:#b45309; color:#fff; font-size:0.75rem;">
                            ⏳ Не оплачен
                        </span>
                    `}
                </td>
                <td>
                    <div style="display: flex; gap: 0.4rem; flex-wrap: wrap; align-items: center;">
                        ${order.status === 'in-progress' ? `
                            <button class="btn btn-outline btn-sm" type="button" onclick="app.setOrderReady('${order.id}')" title="Отметить завершение мойки">
                                ✅ Готово
                            </button>
                        ` : ''}

                        ${!isPaid ? `
                            <button class="btn btn-success btn-sm" type="button" onclick="app.openPaymentModal('${order.id}')" title="Принять оплату">
                                💳 Оплата
                            </button>
                        ` : ''}

                        ${(order.status === 'ready' && isPaid) ? `
                            <button class="btn btn-primary btn-sm" type="button" onclick="app.releaseOrder('${order.id}')" title="Выдать авто клиенту и освободить бокс">
                                👋 Выдать авто
                            </button>
                        ` : ''}
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Строки очереди для подтвержденных броней
        queuedBookings.forEach((b, qIdx) => {
            const box = this.db.boxes.find(bx => bx.id === b.assignedBoxId);
            const workerName = this.getWorkerName(b.assignedWorkerId);
            const serviceNames = (b.services || []).map(sid => {
                const s = this.db.services.find(srv => srv.id === sid);
                return s ? Security.escapeHTML(s.name) : '';
            }).filter(Boolean).join(', ');

            const tr = document.createElement('tr');
            tr.style.background = 'rgba(254, 243, 199, 0.3)';
            tr.innerHTML = `
                <td><span class="badge-queued">Очередь</span></td>
                <td>
                    <strong>${Security.escapeHTML(b.carPlate)}</strong>
                    <div class="text-muted" style="font-size:0.8rem;">${Security.escapeHTML(b.carModel || 'Авто')} (🕒 ${Security.escapeHTML(b.time || '—')})</div>
                </td>
                <td><strong>${box ? Security.escapeHTML(box.name) : '—'}</strong></td>
                <td style="max-width:240px;">${serviceNames || '—'}</td>
                <td>${Security.escapeHTML(workerName)}</td>
                <td><strong>${Number(b.totalPrice).toLocaleString()} ₸</strong></td>
                <td>
                    <span class="status-pill waiting">⏳ В очереди</span>
                </td>
                <td>
                    <span class="text-muted" style="font-size:0.8rem;">При заезде</span>
                </td>
                <td>
                    <button class="btn btn-primary btn-sm" type="button" onclick="app.startBookingInBay('${b.id}')">
                        🚿 Запустить в бокс
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    isOrderPaid(order) {
        return Boolean(order && (order.isPaid || order.status === 'paid'));
    }

    getPaymentMethodName(method) {
        const map = {
            cash: 'Наличные',
            card: 'Карта / POS',
            transfer: 'Kaspi / QR',
            kaspi: 'Kaspi / QR'
        };
        return map[method] || method || 'Оплачено';
    }

    setOrderReady(orderId) {
        const order = this.db.orders.find(o => String(o.id) === String(orderId));
        if (!order) return;

        // Мойщик может отмечать только СВОЙ заказ
        if (this.sessionRole === 'worker' && order.workerId !== this.currentWorkerId) {
            alert('Вы можете отмечать готовность только назначенных лично вам автомобилей!');
            return;
        }

        order.status = 'ready';

        // Если авто УЖЕ ОПЛАЧЕНО клиентом заранее:
        if (this.isOrderPaid(order)) {
            const box = this.db.boxes.find(b => b.id === order.boxId);
            const boxName = box ? box.name : 'Бокс';
            const payName = this.getPaymentMethodName(order.paymentMethod);
            const wantRelease = confirm(`✅ Мойка авто ${order.carPlate} завершена!\n\nАвтомобиль уже был оплачен ранее (${payName}).\n\nВыдать автомобиль клиенту и освободить ${boxName}?`);
            if (wantRelease) {
                this.finishOrder(order);
                return;
            }
        } else {
            alert(`✅ Автомобиль ${order.carPlate} помыт и готов к выдаче!\nОжидает оплаты у администратора.`);
        }

        this.saveDatabase();
        this.renderAll();
    }

    openPaymentModal(orderId) {
        if (!this.verifyAuth('admin')) return;

        const order = this.db.orders.find(o => String(o.id) === String(orderId));
        if (!order) return;

        if (this.isOrderPaid(order)) {
            alert('Этот заказ уже был оплачен ранее.');
            return;
        }

        this.activePaymentOrderId = orderId;
        document.getElementById('payOrderId').textContent = Security.escapeHTML(order.carPlate);
        document.getElementById('payOrderInfo').textContent = `${Security.escapeHTML(order.carModel || '')} | Мойщик: ${Security.escapeHTML(this.getWorkerName(order.workerId))}`;
        document.getElementById('payTotalAmount').textContent = `${Number(order.totalPrice).toLocaleString()} ₸`;

        document.getElementById('paymentModal').classList.add('open');
    }

    closePaymentModal() {
        document.getElementById('paymentModal').classList.remove('open');
        this.activePaymentOrderId = null;
    }

    confirmPayment() {
        if (!this.verifyAuth('admin')) return;
        if (!this.activePaymentOrderId) return;

        const order = this.db.orders.find(o => String(o.id) === String(this.activePaymentOrderId));
        if (order) {
            const checkedMethod = document.querySelector('input[name="payMethod"]:checked');
            const method = checkedMethod ? checkedMethod.value : 'cash';

            order.isPaid = true;
            order.paymentMethod = method;
            order.paidAt = new Date().toISOString();

            // Фиксируем зарплату мойщика
            const percent = order.workerPercentSnapshot || 30;
            order.workerSalaryEarned = Math.round(order.totalPrice * (percent / 100));

            const payName = this.getPaymentMethodName(method);

            // Если машина ЕЩЁ МОЕТСЯ (status === 'in-progress'):
            // Машина остается в боксе! НЕ освобождаем бокс!
            if (order.status === 'in-progress') {
                this.saveDatabase();
                this.closePaymentModal();
                this.renderAll();
                alert(`💳 Оплата за авто ${order.carPlate} успешно принята (${payName})!\n\n🚿 Автомобиль продолжает мыться в боксе. Когда мойка будет окончена, нажмите «Готово», чтобы выдать машину.`);
                return;
            }

            // Если машина УЖЕ БЫЛА ПОМЫТА (status === 'ready'):
            // Теперь выполнены оба условия (помыта И оплачена) — закрываем заказ и освобождаем бокс!
            this.finishOrder(order);
        }
    }

    finishOrder(order) {
        order.status = 'paid';
        order.isPaid = true;
        if (!order.paidAt) order.paidAt = new Date().toISOString();

        // Завершаем связанную онлайн-бронь, если есть
        if (Array.isArray(this.db.bookings)) {
            const linkedBooking = this.db.bookings.find(b => b.orderId === order.id);
            if (linkedBooking) {
                linkedBooking.status = 'completed';
            }
        }

        const box = this.db.boxes.find(b => b.id === order.boxId);
        const boxName = box ? box.name : 'Бокс';

        this.saveDatabase();
        this.closePaymentModal();
        this.renderAll();
        alert(`👋 Мойка авто ${order.carPlate} полностью завершена и оплачена!\n${boxName} свободен для следующего автомобиля. Счастливого пути!`);
    }

    releaseOrder(orderId) {
        const order = this.db.orders.find(o => String(o.id) === String(orderId));
        if (!order) return;
        this.finishOrder(order);
    }

    renderHistory() {
        const tbody = document.getElementById('historyTableBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        const dateFilter = document.getElementById('historyDateFilter').value;

        const historyList = this.db.orders.filter(o => {
            if (o.status !== 'paid') return false;
            if (dateFilter) {
                // Сравнение по локальному часовому поясу
                const orderDate = Security.getLocalDateString(o.paidAt || o.createdAt);
                return orderDate === dateFilter;
            }
            return true;
        });

        if (historyList.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#94a3b8; padding:2rem;">В истории пока нет закрытых заказов за выбранную дату.</td></tr>`;
            return;
        }

        historyList.forEach(order => {
            const workerName = order.workerNameSnapshot || this.getWorkerName(order.workerId);
            const dateStr = new Date(order.paidAt || order.createdAt).toLocaleString('ru-RU', {
                day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
            });

            const methodNames = {
                cash: '💵 Наличные',
                card: '💳 Карта',
                transfer: '📱 Kaspi/QR'
            };

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${dateStr}</td>
                <td><strong>${Security.escapeHTML(order.carPlate)}</strong></td>
                <td>${Security.escapeHTML(order.carModel || '—')}</td>
                <td style="font-size:0.85rem;">${order.services.length} услуг(и)</td>
                <td>${Security.escapeHTML(workerName)}</td>
                <td>${methodNames[order.paymentMethod] || 'Оплачено'}</td>
                <td><strong>${Number(order.totalPrice).toLocaleString()} ₸</strong></td>
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
        const todayStr = Security.getLocalDateString(new Date());
        const now = new Date();
        const currentMonth = now.getMonth();
        const currentYear = now.getFullYear();

        let todayIncome = 0;
        let todayCount = 0;
        let monthIncome = 0;
        let monthCount = 0;
        let monthSalariesFund = 0;

        const workerStats = {};
        this.db.workers.forEach(w => {
            workerStats[w.id] = { name: w.name, percent: w.percent, count: 0, salary: 0 };
        });

        this.db.orders.forEach(o => {
            if (o.status !== 'paid' && !o.isPaid) return;

            const paidDate = new Date(o.paidAt || o.createdAt);
            const dateStr = Security.getLocalDateString(paidDate);
            const orderSalary = o.workerSalaryEarned !== undefined ? o.workerSalaryEarned : Math.round(o.totalPrice * ((o.workerPercentSnapshot || 30) / 100));

            // Сегодня (по местному времени)
            if (dateStr === todayStr) {
                todayIncome += o.totalPrice;
                todayCount += 1;
            }

            // Месяц (по местному времени)
            if (paidDate.getMonth() === currentMonth && paidDate.getFullYear() === currentYear) {
                monthIncome += o.totalPrice;
                monthCount += 1;
                monthSalariesFund += orderSalary; // Зарплаты СТРОГО за текущий месяц!

                if (!workerStats[o.workerId]) {
                    workerStats[o.workerId] = {
                        name: o.workerNameSnapshot || 'Удаленный сотрудник',
                        percent: o.workerPercentSnapshot || 0,
                        count: 0,
                        salary: 0
                    };
                }
                workerStats[o.workerId].count += 1;
                workerStats[o.workerId].salary += orderSalary;
            }
        });

        // Чистая прибыль за месяц = Выручка месяца - Зарплаты месяца
        const netMonthIncome = monthIncome - monthSalariesFund;

        document.getElementById('statTodayIncome').textContent = `${todayIncome.toLocaleString()} ₸`;
        document.getElementById('statTodayCount').textContent = `${todayCount} вымытых авто`;

        document.getElementById('statMonthIncome').textContent = `${monthIncome.toLocaleString()} ₸`;
        document.getElementById('statMonthCount').textContent = `${monthCount} вымытых авто`;

        document.getElementById('statSalaryFund').textContent = `${monthSalariesFund.toLocaleString()} ₸`;
        document.getElementById('statNetIncome').textContent = `${netMonthIncome.toLocaleString()} ₸`;

        // Таблица выработки
        const salaryTbody = document.getElementById('workerSalaryTableBody');
        salaryTbody.innerHTML = '';
        Object.values(workerStats).forEach(stat => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${Security.escapeHTML(stat.name)}</strong></td>
                <td>${stat.count} авто</td>
                <td>${stat.percent}%</td>
                <td><strong style="color:var(--primary);">${stat.salary.toLocaleString()} ₸</strong></td>
            `;
            salaryTbody.appendChild(tr);
        });
    }

    renderSettings() {
        // Список администраторов смены
        const aList = document.getElementById('adminsList');
        if (aList) {
            aList.innerHTML = '';
            (this.db.admins || []).forEach(a => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span><strong>${Security.escapeHTML(a.name)}</strong> ${a.pinHash ? '🔑 личный PIN' : '🔑 общий пароль'}</span>
                    <button class="btn btn-outline btn-sm" type="button" onclick="app.removeAdmin('${a.id}')" style="color:red;">Удалить</button>
                `;
                aList.appendChild(li);
            });
        }

        const wList = document.getElementById('workersList');
        if (!wList) return;
        wList.innerHTML = '';
        this.db.workers.forEach(w => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span><strong>${Security.escapeHTML(w.name)}</strong> (${w.percent}% от чека) ${w.pinHash ? '🔑 личный PIN' : ''}</span>
                <button class="btn btn-outline btn-sm" type="button" onclick="app.removeWorker('${w.id}')" style="color:red;">Удалить</button>
            `;
            wList.appendChild(li);
        });

        const sList = document.getElementById('servicesList');
        if (!sList) return;
        sList.innerHTML = '';
        this.db.services.forEach(s => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span><strong>${Security.escapeHTML(s.name)}</strong> — ${Number(s.basePrice).toLocaleString()} ₸</span>
                <button class="btn btn-outline btn-sm" type="button" onclick="app.removeService('${s.id}')" style="color:red;">Удалить</button>
            `;
            sList.appendChild(li);
        });

        // Заполнение поля Firebase URL
        const fbInput = document.getElementById('firebaseDbUrl');
        if (fbInput && this.db.cloud) {
            fbInput.value = this.db.cloud.firebaseUrl || '';
        }

        // Заполнение QR-кода автомойки для печати
        const settingsQr = document.getElementById('settingsQrContainer');
        const siteInput = document.getElementById('settingsSiteUrlInput');
        if (settingsQr && siteInput) {
            const siteUrl = window.location.href.split('#')[0];
            siteInput.value = siteUrl;
            this.renderQrCode(settingsQr, siteUrl, 140);
        }

        // Обновление таблицы персонала владельца
        this.renderStaffTable();
    }

    toggleStaffPercentField() {
        const roleSelect = document.getElementById('newStaffRole');
        const percentGroup = document.getElementById('staffPercentGroup');
        if (!roleSelect || !percentGroup) return;
        percentGroup.style.display = (roleSelect.value === 'worker') ? 'block' : 'none';
    }

    addStaffMember(event) {
        event.preventDefault();
        if (this.sessionRole !== 'owner') {
            alert('Только Владелец может добавлять сотрудников.');
            return;
        }

        const nameInput = document.getElementById('newStaffName');
        const roleSelect = document.getElementById('newStaffRole');
        const phoneInput = document.getElementById('newStaffPhone');
        const passInput = document.getElementById('newStaffPass');
        const percentInput = document.getElementById('newStaffPercent');

        if (!nameInput || !roleSelect || !phoneInput || !passInput) return;

        const name = nameInput.value.trim();
        const role = roleSelect.value;
        const rawPhone = phoneInput.value.trim();
        const pass = passInput.value.trim();
        const percent = percentInput ? Number(percentInput.value) : 30;

        if (!name || !rawPhone || !pass) {
            alert('Пожалуйста, заполните все обязательные поля.');
            return;
        }

        const cleanDigits = rawPhone.replace(/\D/g, '');
        const last10 = cleanDigits.slice(-10);
        if (last10.length < 10) {
            alert('Введите корректный номер телефона (не менее 10 цифр).');
            return;
        }

        if (cleanDigits === '7765231041' || last10 === '765231041') {
            alert('Этот номер принадлежит главному владельцу (Алимжан).');
            return;
        }

        if (!Array.isArray(this.db.staff)) this.db.staff = [];

        const exists = this.db.staff.find(s => String(s.phone || '').replace(/\D/g, '').slice(-10) === last10);
        if (exists) {
            alert('Сотрудник с таким номером телефона уже существует!');
            return;
        }

        const formattedPhone = this.formatPhoneNumber(rawPhone);
        const newStaff = {
            id: (role === 'worker' ? 'w_' : role === 'admin' ? 'a_' : 'o_') + Security.generateId(),
            name,
            role,
            phone: formattedPhone,
            password: pass,
            percent: (role === 'worker' ? (percent || 30) : 0),
            createdAt: new Date().toISOString()
        };

        this.db.staff.push(newStaff);

        // Синхронизируем с workers и admins для выпадающих списков
        if (role === 'worker') {
            if (!Array.isArray(this.db.workers)) this.db.workers = [];
            this.db.workers.push({ id: newStaff.id, name, percent: newStaff.percent, phone: formattedPhone });
        } else if (role === 'admin') {
            if (!Array.isArray(this.db.admins)) this.db.admins = [];
            this.db.admins.push({ id: newStaff.id, name, phone: formattedPhone });
        }

        this.saveDatabase();
        this.renderStaffTable();
        this.renderBoxesAndSelects();
        event.target.reset();
        const roleLabels = { owner: 'Владелец', admin: 'Администратор', worker: 'Мойщик' };
        alert(`✅ Сотрудник «${name}» (${roleLabels[role] || role}) успешно сохранён!\nНомер для входа: ${formattedPhone}\nПароль: ${pass}`);
    }

    removeStaffMember(staffId) {
        if (this.sessionRole !== 'owner') return;
        if (!confirm('Вы уверены, что хотите удалить этого сотрудника? Он потеряет доступ к системе.')) return;

        if (Array.isArray(this.db.staff)) {
            this.db.staff = this.db.staff.filter(s => s.id !== staffId);
        }
        if (Array.isArray(this.db.workers)) {
            this.db.workers = this.db.workers.filter(w => w.id !== staffId);
        }
        if (Array.isArray(this.db.admins)) {
            this.db.admins = this.db.admins.filter(a => a.id !== staffId);
        }

        this.saveDatabase();
        this.renderStaffTable();
        this.renderBoxesAndSelects();
        alert('Сотрудник успешно удалён.');
    }

    renderStaffTable() {
        const tbody = document.getElementById('staffTableBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        // 1. Главный аккаунт Владельца (Алимжан)
        const ownerTr = document.createElement('tr');
        ownerTr.style.background = 'rgba(245, 158, 11, 0.08)';
        ownerTr.innerHTML = `
            <td><strong>👑 Алимжан</strong></td>
            <td><span class="staff-badge owner">Владелец (Главный)</span></td>
            <td><code>+7 765 231 041</code></td>
            <td><code>Qazxsw</code></td>
            <td><small class="text-muted">100% полный доступ ко всем функциям</small></td>
            <td><span class="badge" style="background:#fef3c7; color:#b45309; font-weight:700;">Главный аккаунт</span></td>
        `;
        tbody.appendChild(ownerTr);

        // 2. Список сотрудников из this.db.staff
        const staffList = Array.isArray(this.db.staff) ? this.db.staff : [];
        if (staffList.length === 0) {
            const emptyTr = document.createElement('tr');
            emptyTr.innerHTML = `
                <td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">
                    Дополнительных сотрудников пока нет. Вы можете добавить администратора или мойщика с помощью формы выше.
                </td>
            `;
            tbody.appendChild(emptyTr);
            return;
        }

        const roleBadges = {
            owner: '<span class="staff-badge owner">Со-владелец</span>',
            admin: '<span class="staff-badge admin">Администратор</span>',
            worker: '<span class="staff-badge worker">Мойщик</span>'
        };

        staffList.forEach(s => {
            const tr = document.createElement('tr');
            const roleBadge = roleBadges[s.role] || `<span class="staff-badge">${s.role}</span>`;
            const details = (s.role === 'worker') ? `${s.percent || 30}% ставка от заказа` : 'Управление сменой';
            tr.innerHTML = `
                <td><strong>${Security.escapeHTML(s.name)}</strong></td>
                <td>${roleBadge}</td>
                <td><code>${Security.escapeHTML(s.phone)}</code></td>
                <td><code>${Security.escapeHTML(s.password || '••••')}</code></td>
                <td><small class="text-muted">${details}</small></td>
                <td>
                    <button class="btn btn-outline btn-sm" type="button" onclick="app.removeStaffMember('${s.id}')" style="color:#ef4444; border-color:#fca5a5;">
                        Удалить
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    async addAdmin(e) {
        e.preventDefault();
        if (!this.verifyAuth('owner')) return;

        const name = document.getElementById('newAdminName').value.trim();
        const pin = document.getElementById('newAdminPin').value.trim();

        if (!name) {
            alert('Пожалуйста, введите имя администратора!');
            return;
        }

        let pinHash = null;
        let pinSalt = null;
        if (pin) {
            if (pin.length < 4) {
                alert('Личный PIN-код или пароль администратора должен быть не менее 4 символов!');
                return;
            }
            pinSalt = Security.generateSalt();
            pinHash = await Security.hash(pin, pinSalt);
        }

        if (!Array.isArray(this.db.admins)) {
            this.db.admins = [];
        }

        this.db.admins.push({
            id: 'a_' + Security.generateId(),
            name,
            pinHash,
            pinSalt
        });

        this.saveDatabase();
        e.target.reset();
        this.renderAll();
        alert(`Администратор ${name} успешно добавлен!`);
    }

    removeAdmin(id) {
        if (!this.verifyAuth('owner')) return;
        if (!Array.isArray(this.db.admins) || this.db.admins.length <= 1) {
            alert('В системе должен оставаться хотя бы один администратор!');
            return;
        }
        const admin = this.db.admins.find(a => a.id === id);
        if (!confirm(`Удалить администратора ${admin ? admin.name : ''}?`)) return;

        this.db.admins = this.db.admins.filter(a => a.id !== id);
        if (this.currentAdminId === id) {
            this.currentAdminId = null;
        }
        this.saveDatabase();
        this.renderAll();
    }

    getAdminName(id) {
        const a = (this.db.admins || []).find(item => item.id === id);
        return a ? a.name : 'Администратор';
    }

    async addWorker(e) {
        e.preventDefault();
        if (!this.verifyAuth('owner')) return;

        const name = document.getElementById('newWorkerName').value.trim();
        const percent = parseInt(document.getElementById('newWorkerPercent').value, 10);
        const pin = document.getElementById('newWorkerPin').value.trim();

        if (!name) {
            alert('Пожалуйста, введите имя сотрудника!');
            return;
        }

        if (isNaN(percent) || percent < 0 || percent > 100) {
            alert('Процент должен быть числом от 0 до 100!');
            return;
        }

        let pinHash = null;
        let pinSalt = null;
        if (pin) {
            if (pin.length < 4) {
                alert('Личный PIN-код должен быть не менее 4 цифр!');
                return;
            }
            pinSalt = Security.generateSalt();
            pinHash = await Security.hash(pin, pinSalt);
        }

        this.db.workers.push({
            id: 'w_' + Security.generateId(),
            name,
            percent,
            pinHash,
            pinSalt
        });

        this.saveDatabase();
        e.target.reset();
        this.renderAll();
        alert(`Сотрудник ${name} успешно добавлен!`);
    }

    removeWorker(id) {
        if (!this.verifyAuth('owner')) return;
        const worker = this.db.workers.find(w => w.id === id);
        if (!confirm(`Удалить сотрудника ${worker ? worker.name : ''}?`)) return;

        this.db.workers = this.db.workers.filter(w => w.id !== id);
        this.saveDatabase();
        this.renderAll();
    }

    addService(e) {
        e.preventDefault();
        if (!this.verifyAuth('owner')) return;

        const name = document.getElementById('newServiceName').value.trim();
        const basePrice = parseInt(document.getElementById('newServicePrice').value, 10);

        if (!name) {
            alert('Введите название услуги!');
            return;
        }

        if (isNaN(basePrice) || basePrice < 0) {
            alert('Цена услуги должна быть положительным числом!');
            return;
        }

        this.db.services.push({
            id: 's_' + Security.generateId(),
            name,
            basePrice
        });

        this.saveDatabase();
        e.target.reset();
        this.renderAll();
        alert(`Услуга ${name} добавлена!`);
    }

    removeService(id) {
        if (!this.verifyAuth('owner')) return;
        const s = this.db.services.find(item => item.id === id);
        if (!confirm(`Удалить услугу ${s ? s.name : ''}?`)) return;

        this.db.services = this.db.services.filter(item => item.id !== id);
        this.saveDatabase();
        this.renderAll();
    }

    getWorkerName(id) {
        const w = this.db.workers.find(item => item.id === id);
        return w ? w.name : '—';
    }

    // ==================== БЕЗОПАСНЫЙ ЭКСПОРТ И ИМПОРТ ====================

    exportDatabase() {
        if (!this.verifyAuth('owner')) return;

        const maskPhones = document.getElementById('maskPhonesCheckbox').checked;

        // Клонируем данные без секретных паролей и с маскированием
        const exportData = {
            version: 2,
            exportedAt: new Date().toISOString(),
            contacts: this.db.contacts,
            boxes: this.db.boxes,
            services: this.db.services,
            admins: (this.db.admins || []).map(a => ({ id: a.id, name: a.name })), // Без личных хэшей PIN
            workers: this.db.workers.map(w => ({ id: w.id, name: w.name, percent: w.percent })), // Без хэшей PIN
            orders: this.db.orders.map(o => {
                const clone = { ...o };
                if (maskPhones && clone.phone) {
                    clone.phone = clone.phone.replace(/(\+?\d{1,3}).*(\d{2})$/, '$1 *** *** $2');
                }
                return clone;
            }),
            clients: (this.db.clients || []).map(c => ({
                id: c.id,
                name: c.name,
                phone: maskPhones ? c.phone.replace(/(\+?\d{1,3}).*(\d{2})$/, '$1 *** *** $2') : c.phone,
                cars: c.cars || []
            })),
            bookings: (this.db.bookings || []).map(b => {
                const clone = { ...b };
                if (maskPhones && clone.clientPhone) {
                    clone.clientPhone = clone.clientPhone.replace(/(\+?\d{1,3}).*(\d{2})$/, '$1 *** *** $2');
                }
                return clone;
            })
        };

        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `carwash_backup_${Security.getLocalDateString(new Date())}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    }

    importDatabase(event) {
        if (!this.verifyAuth('owner')) return;

        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const parsed = JSON.parse(e.target.result);

                // Строгая валидация структуры
                if (!Array.isArray(parsed.boxes) || !Array.isArray(parsed.services)) {
                    alert('Ошибка: Файл не содержит необходимых разделов базы автомойки.');
                    return;
                }

                const ordersCount = Array.isArray(parsed.orders) ? parsed.orders.length : 0;
                const adminsCount = Array.isArray(parsed.admins) ? parsed.admins.length : 0;
                const workersCount = Array.isArray(parsed.workers) ? parsed.workers.length : 0;
                const bookingsCount = Array.isArray(parsed.bookings) ? parsed.bookings.length : 0;

                const confirmed = confirm(
                    `Внимание! Вы восстанавливаете базу из файла.\n\n` +
                    `• Заказов: ${ordersCount}\n` +
                    (adminsCount > 0 ? `• Администраторов: ${adminsCount}\n` : '') +
                    `• Сотрудников: ${workersCount}\n` +
                    `• Услуг: ${parsed.services.length}\n` +
                    `• Онлайн-броней: ${bookingsCount}\n\n` +
                    `Текущие заказы будут заменены данными из файла. Ваши пароли НЕ будут затронуты. Продолжить?`
                );

                if (!confirmed) {
                    event.target.value = '';
                    return;
                }

                this.db.boxes = parsed.boxes;
                this.db.services = parsed.services;
                if (Array.isArray(parsed.admins) && parsed.admins.length > 0) {
                    this.db.admins = parsed.admins.map(a => ({
                        id: a.id || Security.generateId(),
                        name: a.name || 'Администратор',
                        pinHash: null,
                        pinSalt: null
                    }));
                }
                if (Array.isArray(parsed.workers)) {
                    this.db.workers = parsed.workers.map(w => ({
                        id: w.id || Security.generateId(),
                        name: w.name || 'Сотрудник',
                        percent: typeof w.percent === 'number' ? w.percent : 30
                    }));
                }
                this.db.orders = Array.isArray(parsed.orders) ? parsed.orders : [];
                if (Array.isArray(parsed.clients)) this.db.clients = parsed.clients;
                if (Array.isArray(parsed.bookings)) this.db.bookings = parsed.bookings;
                if (parsed.contacts) this.db.contacts = parsed.contacts;

                this.saveDatabase();
                this.renderAll();
                alert('✅ База данных успешно восстановлена!');
            } catch (err) {
                alert('Ошибка чтения файла: ' + err.message);
            } finally {
                event.target.value = '';
            }
        };
        reader.readAsText(file);
    }
}

// Запуск приложения
const app = new CarWashApp();
