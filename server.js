/**
 * Serveur de signalisation WebRTC — pour relier deux appareils
 * (un "contrôleur" et un "contrôlé") appartenant au même utilisateur.
 *
 * Rôle de ce serveur : UNIQUEMENT faire se rencontrer les deux appareils
 * et transmettre les messages de signalisation WebRTC (offer/answer/ICE).
 * Il ne voit JAMAIS le flux vidéo ni les commandes une fois la connexion
 * WebRTC établie (celle-ci est directe et chiffrée, de pair à pair).
 *
 * Sécurité :
 * - Chaque "session" est identifiée par un code de pairage à 6 chiffres,
 *   généré par l'appareil "hôte" (celui qui sera contrôlé).
 * - Le code expire après 5 minutes s'il n'est pas utilisé.
 * - Une fois les deux appareils connectés, le code est invalidé.
 * - Un jeton secret (déviceToken) est requis pour reprendre une session
 *   existante, afin qu'un tiers ne puisse pas s'insérer avec le code.
 */

const WebSocket = require('ws');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.join(__dirname, 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

// Serveur HTTP classique : sert la page contrôleur (public/controller.html)
// en plus d'accepter les connexions WebSocket sur la même adresse/port.
// Ça permet un déploiement unique : une seule URL pour tout le projet.
const httpServer = http.createServer((req, res) => {
  let filePath = req.url.split('?')[0];
  if (filePath === '/') filePath = '/index.html';
  const fullPath = path.join(PUBLIC_DIR, filePath);

  // Empêche de sortir du dossier public (sécurité basique)
  if (!fullPath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Interdit');
  }

  fs.readFile(fullPath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Page introuvable');
    }
    const ext = path.extname(fullPath);
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(content);
  });
});

// Le serveur WebSocket se greffe sur le même serveur HTTP (même port).
const wss = new WebSocket.Server({ server: httpServer });

// sessions: code -> { host, controller, createdAt, hostToken, controllerToken }
const sessions = new Map();

const CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes pour se connecter
const SESSION_IDLE_TTL_MS = 60 * 60 * 1000; // 1h d'inactivité max

function generateCode() {
  // Code numérique à 6 chiffres, facile à saisir sur un téléphone
  return crypto.randomInt(100000, 999999).toString();
}

function generateToken() {
  return crypto.randomBytes(24).toString('hex');
}

function send(ws, type, payload = {}) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type, ...payload }));
  }
}

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [code, session] of sessions.entries()) {
    const isPaired = session.host && session.controller;
    const ttl = isPaired ? SESSION_IDLE_TTL_MS : CODE_TTL_MS;
    if (now - session.lastActivity > ttl) {
      send(session.host, 'session-expired');
      send(session.controller, 'session-expired');
      sessions.delete(code);
      console.log(`[cleanup] Session ${code} expirée et supprimée`);
    }
  }
}
setInterval(cleanupExpiredSessions, 30 * 1000);

wss.on('connection', (ws) => {
  ws.id = crypto.randomUUID();
  ws.role = null;
  ws.code = null;

  console.log(`[connexion] Nouveau client ${ws.id}`);

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (e) {
      return send(ws, 'error', { message: 'JSON invalide' });
    }

    switch (msg.type) {
      // ---- 1. L'appareil "hôte" (celui qui sera contrôlé) démarre une session ----
      case 'host-create-session': {
        const code = generateCode();
        const hostToken = generateToken();
        sessions.set(code, {
          host: ws,
          controller: null,
          hostToken,
          controllerToken: null,
          createdAt: Date.now(),
          lastActivity: Date.now(),
        });
        ws.role = 'host';
        ws.code = code;
        send(ws, 'session-created', { code, hostToken });
        console.log(`[session] Code créé: ${code}`);
        break;
      }

      // ---- 2. L'appareil "contrôleur" rejoint avec le code affiché sur l'hôte ----
      case 'controller-join-session': {
        const session = sessions.get(msg.code);
        if (!session) {
          return send(ws, 'error', { message: 'Code invalide ou expiré' });
        }
        if (session.controller) {
          return send(ws, 'error', { message: 'Cette session a déjà un contrôleur' });
        }
        const controllerToken = generateToken();
        session.controller = ws;
        session.controllerToken = controllerToken;
        session.lastActivity = Date.now();
        ws.role = 'controller';
        ws.code = msg.code;

        send(ws, 'joined-session', { code: msg.code, controllerToken });
        send(session.host, 'peer-connected'); // signale à l'hôte qu'un contrôleur est arrivé
        console.log(`[session] Contrôleur connecté sur le code ${msg.code}`);
        break;
      }

      // ---- 3. Reprise d'une session existante avec un token (reconnexion) ----
      case 'resume-session': {
        const session = sessions.get(msg.code);
        if (!session) return send(ws, 'error', { message: 'Session introuvable' });

        if (msg.role === 'host' && msg.token === session.hostToken) {
          session.host = ws;
          ws.role = 'host';
          ws.code = msg.code;
          send(ws, 'resumed', { code: msg.code });
        } else if (msg.role === 'controller' && msg.token === session.controllerToken) {
          session.controller = ws;
          ws.role = 'controller';
          ws.code = msg.code;
          send(ws, 'resumed', { code: msg.code });
        } else {
          send(ws, 'error', { message: 'Jeton invalide' });
        }
        break;
      }

      // ---- 4. Relais des messages WebRTC (offer / answer / ICE candidates) ----
      case 'signal': {
        const session = sessions.get(ws.code);
        if (!session) return send(ws, 'error', { message: 'Session inconnue' });

        session.lastActivity = Date.now();
        const target = ws.role === 'host' ? session.controller : session.host;
        send(target, 'signal', { data: msg.data, from: ws.role });
        break;
      }

      // ---- 5. Fin de session volontaire ----
      case 'end-session': {
        const session = sessions.get(ws.code);
        if (session) {
          const other = ws.role === 'host' ? session.controller : session.host;
          send(other, 'session-ended');
          sessions.delete(ws.code);
          console.log(`[session] ${ws.code} terminée par ${ws.role}`);
        }
        break;
      }

      default:
        send(ws, 'error', { message: `Type de message inconnu: ${msg.type}` });
    }
  });

  ws.on('close', () => {
    console.log(`[déconnexion] Client ${ws.id} (${ws.role || 'sans rôle'})`);
    if (ws.code) {
      const session = sessions.get(ws.code);
      if (session) {
        const other = ws.role === 'host' ? session.controller : session.host;
        send(other, 'peer-disconnected');
        // On ne supprime pas la session tout de suite : on laisse une chance
        // de reconnexion via 'resume-session' avant expiration (SESSION_IDLE_TTL_MS).
      }
    }
  });
});

httpServer.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
  console.log(`Page contrôleur : http://localhost:${PORT}/controller.html`);
  console.log(`WebSocket de signalisation : ws://localhost:${PORT}`);
});
