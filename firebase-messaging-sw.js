// Lunox — service worker для Firebase Cloud Messaging (фоновые push-уведомления).
// Регистрируется из index.html со scope '/firebase-cloud-messaging-push-scope',
// чтобы не конфликтовать с PWA-воркером /service-worker.js (scope '/').
// Конфиг — тот же, что в index.html (firebaseConfig); версия SDK совпадает с подключённой там.
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyCQL-Jk4WHAoECmdz0povAcZilOvvtQPR4",
  authDomain: "lunoh-5453a.firebaseapp.com",
  projectId: "lunoh-5453a",
  storageBucket: "lunoh-5453a.firebasestorage.app",
  messagingSenderId: "785370062580",
  appId: "1:785370062580:web:4e24ba818086af8103c8a1"
});

const messaging = firebase.messaging();

// Сообщения с полем "notification" SDK показывает сам. Здесь — только data-only push.
messaging.onBackgroundMessage((payload) => {
  if (payload.notification) return;
  const d = payload.data || {};
  return self.registration.showNotification(d.title || 'Lunox', {
    body: d.body || '',
    icon: '/icon-192.png',
    badge: '/icon-192.png'
  });
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if ('focus' in c) return c.focus();
      }
      return self.clients.openWindow('/');
    })
  );
});
