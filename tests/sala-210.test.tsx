import { expect, mock, test } from 'claude-code/testing'

// ponte 2.10 no painel: sala trancada (trancar, admitidos, admitir, recusar), relay reserva por escolha, estante da
// sala, entrega guardada e segundo dono do escritório.

const ok = (stdout: string) => ({ value: { exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } })
const nao = (stderr: string) => ({ value: { exitCode: 1, stdout: '', stderr, isStdoutTruncated: false, isStderrTruncated: false } })

const JP3 = 'JP3.' + 'A'.repeat(22) + '.' + 'B'.repeat(43) + '.20768.' + 'aHR0cHM6Ly9zYWxhLWphcnZpcy5wcmFnbWEtaWEud29ya2Vycy5kZXY'
const E1 = 'E1.' + 'C'.repeat(22) + '.' + 'D'.repeat(43) + '.20768.' + 'aHR0cHM6Ly9zYWxhLWphcnZpcy5wcmFnbWEtaWEud29ya2Vycy5kZXY'

type Mundo = {
  salas: Record<string, Record<string, unknown>>
  chamadas: string[][]
  toasts: string[]
  status: string[]
  caixa: { novas: number; pedidos: number; de: string[]; esperando: number }
  escritorio: boolean
}

function motor(on: any, mundo: Mundo) {
  const relogio = mock.clock(on, { now: 1_800_000_000_000 })
  mock.store(on)
  on('command.register', () => ({ value: { command: 'sala' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.close', () => ({ value: undefined }))
  on('ui.panes', () => ({ value: [] }))
  on('ui.copy', () => ({ value: { isCopied: true } }))
  on('ui.toast', (_: any, e: any) => {
    mundo.toasts.push(String(e?.text ?? e))
    return { value: undefined }
  })
  on('ui.status', (_: any, e: any) => {
    mundo.status.push(String(e?.text ?? e))
    return { value: undefined }
  })
  on('session.start', (_: any, e: any) => ({ cwd: e.cwd }))
  on('process.run', (_: any, e: any) => {
    mundo.chamadas.push([...e.argv])
    const a = e.argv.join(' ')
    if (a.includes('--version')) return ok('Python 3.12.3')
    if (a.includes('salas --json')) return ok(JSON.stringify(mundo.salas))
    if (a.includes(' presenca ')) return ok('Presença: estou aqui.')
    if (a.includes('caixa --espiar')) return ok(JSON.stringify(mundo.caixa))
    if (a.includes(' caixa')) return ok('=== CARTA · de: Clara ===')
    if (a.includes('escritorio criar')) {
      mundo.salas.pragma = { nome: 'agente de Ana', humano: 'Ana', servidor: 'https://sala-jarvis.pragma-ia.workers.dev', usada_em: '2026-11-12T01:00:00' }
      return ok(`Escritório 'PRAGMA' criado (corredor: sala 'pragma').\n\n${E1}\n\nLINK: https://sala-jarvis.pages.dev/escritorio.html#${E1}\n`)
    }
    if (a.includes('escritorio entrar')) {
      mundo.salas.andar = { nome: 'agente de Ana', humano: 'Ana', servidor: 'https://sala-jarvis.pragma-ia.workers.dev', usada_em: '2026-11-12T01:00:00' }
      return ok("Entrou no corredor do escritório (sala 'andar') como 'agente de Ana'.")
    }
    if (a.includes('escritorio ver')) return ok('ESCRITÓRIO PRAGMA · corredor \'pragma\' · 2 membro(s)\n\nMESAS\n  ● agente de Ana (você) · agente · de plantão')
    if (a.includes('escritorio quadro')) return ok('[pedido] Fechar o orçamento · cartão ab12cd34 · de Ana · sem dono')
    if (a.includes('escritorio pedir')) return ok('Pedido posto no quadro do escritório \'pragma\': "Fechar o orçamento" para Clara · cartão ab12cd34.')
    if (a.includes('escritorio aprovar')) return ok('Cartão ab12cd34 ("Fechar o orçamento") APROVADO.')
    if (a.includes('escritorio devolver')) return ok('Cartão ab12cd34 ("Fechar o orçamento") DEVOLVIDO.')
    if (a.includes('escritorio recibo')) return ok('Recibo do cartão ab12cd34 gravado em /tmp/recibo-ab12cd34.json')
    if (a.includes('escritorio cerebro buscar')) return ok('CÉREBRO · 1 nota(s) sobre "bdi"\n[decisão] BDI padrão de 28% · nota 11aa22bb')
    if (a.includes('escritorio cerebro ver')) return ok("CÉREBRO DO ESCRITÓRIO 'pragma' · 3 nota(s)")
    if (a.includes(' dizer ')) return ok('Enviada para a sala.')
    if (/ (trancar|destrancar) /.test(' ' + a + ' ')) return ok(a.includes('destrancar') ? 'Sala destrancada.' : 'Sala TRANCADA: quem entrar pelo link vira pedido de entrada.')
    if (a.includes(' admitidos ')) return ok('Sala trancada · relay reserva ligado\nPEDIDOS DE ENTRADA\n  Clara (código 1a2b 3c4d 5e6f 7a8b)')
    if (a.includes(' admitir ')) return ok('Clara admitida: a conversa abre para ela.')
    if (a.includes(' recusar ')) return ok('Pedido de Clara recusado.')
    if (a.includes(' reserva ')) return ok(a.includes('desligar') ? 'Relay reserva DESLIGADO nesta sala.' : 'Relay reserva ligado nesta sala.')
    if (a.includes(' estante ')) return ok(a.includes(' ler ') ? 'regras: Medição toda sexta.' : 'ESTANTE DA SALA · 1 documento(s)\n  regras')
    if (a.includes('escritorio entrega baixar')) return ok('Entrega do cartão ab12cd34 baixada em /tmp/fundacao.csv (sha256 confere).')
    if (a.includes('escritorio dono')) return ok('Clara agora é segundo dono do escritório.')
    if (a.includes(' criar ')) return ok(`Sala 'nova' criada. Mande o LINK:\n\n${JP3}\n\nLINK: https://sala-jarvis.pages.dev/#${JP3}\n`)
    if (a.includes(' convite ')) return ok(JP3 + '\n')
    if (a.includes(' entrar ')) {
      mundo.salas.carlos = { nome: 'agente de Ana', humano: 'Ana', servidor: 'https://sala-jarvis.pragma-ia.workers.dev', usada_em: '2026-11-12T02:00:00' }
      return ok("Entrou na sala 'carlos' como 'agente de Ana'.")
    }
    return nao('chamada não prevista: ' + a)
  })
  on('process.spawn', async function* (_: any, e: any) {
    const argv: string[] = [...(e?.argv ?? [])]
    const sala = argv[argv.indexOf('--sala') + 1] ?? '?'
    yield {
      stream: 'stdout',
      text: JSON.stringify({ tipo: 'conectado', sala, eu: 'agente de Ana', humano: 'Ana', versao: '2.8', ouvindo: true, vivo: true, sf: true, escritorio: mundo.escritorio }) + '\n',
    }
    yield { stream: 'stdout', text: JSON.stringify({ tipo: 'servico', t: 'entrada', de: 'Clara', origem: 'agente-externo', papel: 'agente', time: 1_800_000_000 }) + '\n' }
    yield { stream: 'stdout', text: JSON.stringify({ tipo: 'servico', t: 'chave', de: 'Clara', origem: 'agente-externo', papel: 'agente', time: 1_800_000_001 }) + '\n' }
    yield { stream: 'stdout', text: JSON.stringify({ tipo: 'fixo', slot: 'quadro:abcd', time: 1_800_000_002 }) + '\n' }
    await relogio.sleep(24 * 60 * 60 * 1000)
    return { value: { code: 0, signal: null } }
  })
  return relogio
}

function novoMundo(): Mundo {
  return {
    salas: { amigo: { nome: 'agente de Ana', humano: 'Ana', servidor: 'https://ntfy.sh', usada_em: '2026-11-07T17:33:00' } },
    chamadas: [],
    toasts: [],
    status: [],
    caixa: { novas: 0, pedidos: 0, de: [], esperando: 0 },
    escritorio: false,
  }
}

test('2.10: /sala trancar, admitidos, admitir e recusar falam com a ponte na sala ativa', async ($, on) => {
  const mundo = novoMundo()
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const t = await $.command.run({ command: 'sala', args: 'trancar' })
  expect(String(t?.text)).toContain('TRANCADA')
  expect(mundo.chamadas.find(c => c.includes('trancar'))!.slice(-3)).toEqual(['trancar', '--sala', 'amigo'])
  const ad = await $.command.run({ command: 'sala', args: 'admitidos' })
  expect(String(ad?.text)).toContain('PEDIDOS DE ENTRADA')
  const sim = await $.command.run({ command: 'sala', args: 'admitir Clara' })
  expect(String(sim?.text)).toContain('admitida')
  expect(mundo.chamadas.find(c => c.includes('admitir'))!.slice(-4)).toEqual(['admitir', 'Clara', '--sala', 'amigo'])
  const sem = await $.command.run({ command: 'sala', args: 'admitir' })
  expect(String(sem?.text)).toContain('Diga quem')
  const nao = await $.command.run({ command: 'sala', args: 'recusar Clara' })
  expect(String(nao?.text)).toContain('recusado')
})

test('2.10: /sala reserva desliga e liga; /sala estante lista e lê o contexto da sala', async ($, on) => {
  const mundo = novoMundo()
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const d = await $.command.run({ command: 'sala', args: 'reserva desliga' })
  expect(String(d?.text)).toContain('DESLIGADO')
  expect(mundo.chamadas.find(c => c.includes('reserva'))!.slice(-4)).toEqual(['reserva', 'desligar', '--sala', 'amigo'])
  const v = await $.command.run({ command: 'sala', args: 'estante' })
  expect(String(v?.text)).toContain('ESTANTE DA SALA')
  const l = await $.command.run({ command: 'sala', args: 'estante regras' })
  expect(String(l?.text)).toContain('Medição toda sexta')
  expect(mundo.chamadas.find(c => c.includes('estante') && c.includes('ler'))!.slice(-5)).toEqual(['estante', 'ler', 'regras', '--sala', 'amigo'])
})

test('2.10: /sala entrega baixa a entrega guardada e /sala dono dar faz um segundo dono', async ($, on) => {
  const mundo = novoMundo()
  mundo.escritorio = true
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const e = await $.command.run({ command: 'sala', args: 'entrega ab12cd34' })
  expect(String(e?.text)).toContain('sha256 confere')
  const ruim = await $.command.run({ command: 'sala', args: 'entrega' })
  expect(String(ruim?.text)).toContain('Diga o cartão')
  const dd = await $.command.run({ command: 'sala', args: 'dono dar Clara' })
  expect(String(dd?.text)).toContain('segundo dono')
  const c = mundo.chamadas.find(x => x.includes('dono'))!
  expect(c.slice(c.indexOf('escritorio'), c.indexOf('escritorio') + 4)).toEqual(['escritorio', 'dono', 'dar', 'Clara'])
  const uso = await $.command.run({ command: 'sala', args: 'dono Clara' })
  expect(String(uso?.text)).toContain('Use: /sala dono dar')
})
