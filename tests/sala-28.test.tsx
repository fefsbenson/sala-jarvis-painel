import { expect, mock, test } from 'claude-code/testing'

// ponte 2.8 no painel: convite JP3 (sigilo futuro) e E1 (escritório) em /sala nova, convidar e entrar; o andar em
// texto (/sala escritorio), o quadro de entregas falado pelo humano (/sala pedir, aprovar, devolver), o pedido de
// reenvio e o aviso de carta nova na caixa de entrada.

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

test('JP3: /sala nova devolve o link, /sala convidar copia e /sala entrar aceita o link de sala com sigilo futuro', async ($, on) => {
  const mundo = novoMundo()
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  mundo.salas.nova = { nome: 'agente de Ana', humano: 'Ana', servidor: 'https://sala-jarvis.pragma-ia.workers.dev', usada_em: '2026-11-12T03:00:00' }
  const nova = await $.command.run({ command: 'sala', args: 'nova nova-2' })
  expect(String(nova?.text)).toContain(`https://sala-jarvis.pages.dev/#${JP3}`)
  const conv = await $.command.run({ command: 'sala', args: 'convidar' })
  expect(String(conv?.text)).toContain(JP3)
  const entrou = await $.command.run({ command: 'sala', args: `entrar https://sala-jarvis.pages.dev/#${JP3} carlos` })
  expect(String(entrou?.text)).toContain("Entrei na sala 'carlos'")
  const e = mundo.chamadas.find(c => c.includes('entrar') && !c.includes('escritorio'))!
  expect(e[e.indexOf('entrar') + 1]).toBe(JP3)
})

test('escritório: o link E1 entra pelo corredor, /sala escritorio criar devolve o link do andar e /sala escritorio mostra o andar', async ($, on) => {
  const mundo = novoMundo()
  mundo.escritorio = true
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const entrou = await $.command.run({ command: 'sala', args: `entrar https://sala-jarvis.pages.dev/escritorio.html#${E1} andar` })
  expect(String(entrou?.text)).toContain("Entrei na sala 'andar'")
  const e = mundo.chamadas.find(c => c.includes('escritorio') && c.includes('entrar'))!
  expect(e.slice(e.indexOf('escritorio'), e.indexOf('escritorio') + 3)).toEqual(['escritorio', 'entrar', E1])
  const criou = await $.command.run({ command: 'sala', args: 'escritorio criar PRAGMA' })
  expect(String(criou?.text)).toContain(`https://sala-jarvis.pages.dev/escritorio.html#${E1}`)
  const c = mundo.chamadas.find(x => x.includes('escritorio') && x.includes('criar'))!
  expect(c.slice(c.indexOf('criar'))).toEqual(['criar', 'PRAGMA', '--agente', 'agente de Ana', '--humano', 'Ana', '--apelido', 'pragma'])
  await relogio.settle()
  const andar = await $.command.run({ command: 'sala', args: 'escritorio' })
  expect(String(andar?.text)).toContain('ESCRITÓRIO PRAGMA')
  const v = mundo.chamadas.filter(x => x.includes('escritorio') && x.includes('ver')).at(-1)!
  expect(v.slice(-2)).toEqual(['--sala', 'pragma']) // o painel está no corredor: é desse escritório que se fala
})

test('quadro pelo painel: o humano pede (com @Nome), aprova e devolve; os comandos saem em nome do humano', async ($, on) => {
  const mundo = novoMundo()
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const pediu = await $.command.run({ command: 'sala', args: 'pedir Fechar o orçamento @Clara' })
  expect(String(pediu?.text)).toContain('cartão ab12cd34')
  const p = mundo.chamadas.find(x => x.includes('pedir'))!
  expect(p.slice(p.indexOf('pedir'))).toEqual(['pedir', 'Fechar o orçamento', '--humano', '--para', 'Clara'])
  await $.command.run({ command: 'sala', args: 'aprovar ab12cd34 ficou bom' })
  const a = mundo.chamadas.find(x => x.includes('aprovar'))!
  expect(a.slice(a.indexOf('aprovar'))).toEqual(['aprovar', 'ab12cd34', '--humano', '--nota', 'ficou bom'])
  await $.command.run({ command: 'sala', args: 'devolver ab12cd34 falta a obra C' })
  const d = mundo.chamadas.find(x => x.includes('devolver'))!
  expect(d.slice(d.indexOf('devolver'))).toEqual(['devolver', 'ab12cd34', '--humano', '--nota', 'falta a obra C'])
  const recibo = await $.command.run({ command: 'sala', args: 'recibo ab12cd34' })
  expect(String(recibo?.text)).toContain('Recibo do cartão ab12cd34')
  const rc = mundo.chamadas.find(x => x.includes('recibo'))!
  expect(rc.slice(rc.indexOf('recibo')).slice(0, 2)).toEqual(['recibo', 'ab12cd34'])
  const cz = await $.command.run({ command: 'sala', args: 'cerebro' })
  expect(String(cz?.text)).toContain('CÉREBRO DO ESCRITÓRIO')
  const czb = await $.command.run({ command: 'sala', args: 'cerebro qual bdi usar' })
  expect(String(czb?.text)).toContain('BDI padrão de 28%')
  const cb = mundo.chamadas.find(x => x.includes('buscar'))!
  expect(cb.slice(cb.indexOf('cerebro')).slice(0, 3)).toEqual(['cerebro', 'buscar', 'qual bdi usar'])
  const semId = await $.command.run({ command: 'sala', args: 'aprovar' })
  expect(String(semId?.text)).toContain('Diga o cartão')
  const quadro = await $.command.run({ command: 'sala', args: 'quadro' })
  expect(String(quadro?.text)).toContain('Fechar o orçamento')
})

test('/sala reenviar pede o reenvio na sala, como fala do humano', async ($, on) => {
  const mundo = novoMundo()
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const r = await $.command.run({ command: 'sala', args: 'reenviar 0123456789abcdef' })
  expect(String(r?.text)).toContain('Pedido de reenvio')
  const d = mundo.chamadas.find(x => x.includes('dizer'))!
  expect(d.slice(d.indexOf('dizer'))).toEqual(['dizer', '--sala', 'amigo', '[REENVIAR] 0123456789abcdef'])
  const ruim = await $.command.run({ command: 'sala', args: 'reenviar xyz' })
  expect(String(ruim?.text)).toContain('Diga o id')
})

test('aviso de carta nova: a caixa é conferida sem consumir, avisa uma vez por quantidade e some depois de /sala caixa', async ($, on) => {
  const mundo = novoMundo()
  mundo.caixa = { novas: 2, pedidos: 1, de: ['Clara', 'Bruno'], esperando: 0 }
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  await relogio.advance(6 * 60 * 1000)
  await relogio.settle()
  const avisos = () => mundo.toasts.filter(t => t.includes('Caixa de entrada'))
  expect(avisos().length).toBe(1)
  expect(avisos()[0]).toContain('2 cartas novas (Clara, Bruno)')
  expect(mundo.chamadas.some(c => c.join(' ').includes('caixa --espiar'))).toBe(true)
  await relogio.advance(6 * 60 * 1000)
  await relogio.settle()
  expect(avisos().length).toBe(1) // a mesma quantidade não avisa de novo
  const lida = await $.command.run({ command: 'sala', args: 'caixa' })
  expect(String(lida?.text)).toContain('CARTA')
  mundo.caixa = { novas: 1, pedidos: 0, de: ['Clara'], esperando: 0 }
  await relogio.advance(6 * 60 * 1000)
  await relogio.settle()
  expect(avisos().length).toBe(2)
  expect(avisos()[1]).toContain('1 carta nova (Clara)')
})
