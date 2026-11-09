import { expect, mock, test } from 'claude-code/testing'

// ponte 2.7 no painel: seguir a sala que o agente desta sessão está ouvindo (HAR-005), links JP2 em
// /sala nova, /sala convidar e /sala entrar, e a atividade que vale pela 'dura' até o agente voltar a ouvir.

const ok = (stdout: string) => ({ value: { exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } })
const nao = (stderr: string) => ({ value: { exitCode: 1, stdout: '', stderr, isStdoutTruncated: false, isStderrTruncated: false } })

const PANE = {
  plugin: 'sala',
  component: 'Pane',
  requestId: 'sala',
  props: { title: 'Sala', isFocused: true, bodyColumns: 70, placement: 'dock', scroll: { offset: 0, bodyRows: 60 }, view: {} },
} as const

const JP2 = 'JP2.' + 'A'.repeat(22) + '.' + 'B'.repeat(43) + '.20400'

type Mundo = {
  salas: Record<string, Record<string, unknown>>
  hook: Record<string, unknown>
  linhas: Record<string, object[]>
  chamadas: string[][]
  espiadas: string[]
  toasts: string[]
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
  on('ui.status', () => ({ value: undefined }))
  on('session.start', (_: any, e: any) => ({ cwd: e.cwd }))
  on('process.run', (_: any, e: any) => {
    mundo.chamadas.push([...e.argv])
    const a = e.argv.join(' ')
    if (a.includes('--version')) return ok('Python 3.12.3')
    if (a.includes('salas --json')) return ok(JSON.stringify(mundo.salas))
    if (a.includes(' atividade ')) return ok(JSON.stringify(mundo.hook) + '\n')
    if (a.includes(' presenca ')) return ok('Presença: estou aqui.')
    if (a.includes(' criar ')) return ok(`Sala 'carlos' criada. Mande o LINK:\n\n${JP2}\n\nLINK: https://sala-jarvis.pages.dev/#${JP2}\n`)
    if (a.includes(' convite ')) return ok(JP2 + '\n')
    if (a.includes(' encerrar ')) return ok("Sala 'reuniao' ENCERRADA para todos.")
    if (a.includes(' mandar ')) return ok('Carta com o convite da sala deixada na caixa.')
    if (a.includes('endereco --json')) return ok(JSON.stringify({ endereco: 'jv1' + 'a'.repeat(58), codigo: '1234 5678 9abc def0' }))
    if (a.includes(' entrar ')) {
      mundo.salas.carlos = { nome: 'JARVIS da Ana', humano: 'Ana', servidor: 'https://ntfy.sh', usada_em: '2026-11-09T03:00:00' }
      return ok("Entrou na sala 'carlos' como 'JARVIS da Ana'.")
    }
    return nao('chamada não prevista: ' + a)
  })
  on('process.spawn', async function* (_: any, e: any) {
    const argv: string[] = [...(e?.argv ?? [])]
    const sala = argv[argv.indexOf('--sala') + 1] ?? '?'
    mundo.espiadas.push(sala)
    yield { stream: 'stdout', text: JSON.stringify({ tipo: 'conectado', sala, eu: 'JARVIS da Ana', humano: 'Ana', versao: '2.7', ouvindo: true, vivo: true }) + '\n' }
    for (const l of mundo.linhas[sala] ?? []) yield { stream: 'stdout', text: JSON.stringify(l) + '\n' }
    await relogio.sleep(24 * 60 * 60 * 1000)
    return { value: { code: 0, signal: null } }
  })
  return relogio
}

function novoMundo(): Mundo {
  return {
    salas: {
      amigo: { nome: 'JARVIS da Ana', humano: 'Ana', servidor: 'https://ntfy.sh', usada_em: '2026-11-07T17:33:00', em_reuniao: false, desta_sessao: false },
      reuniao: { nome: 'JARVIS da Ana', humano: 'Ana', servidor: 'https://ntfy.sh', usada_em: '2026-11-06T10:00:00', em_reuniao: false, desta_sessao: false },
    },
    hook: { sala: null, publicado: false, motivo: 'nenhuma sala em reunião nesta sessão', pedida: 'amigo' },
    linhas: {},
    chamadas: [],
    espiadas: [],
    toasts: [],
  }
}

test('HAR-005: o trabalho sai na sala que o agente desta sessão ouve, e o painel passa a mostrá-la', async ($, on) => {
  const mundo = novoMundo()
  const relogio = motor(on, mundo)
  on('tool.call', () => ({ result: {} }))
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  // o painel começa na sala mais recente (amigo), como o painel de 08/11
  expect(mundo.espiadas.at(-1)).toBe('amigo')
  // o agente desta sessão entra em reunião na reuniao; a ponte manda o trabalho para lá e diz qual foi
  mundo.salas.reuniao = { ...mundo.salas.reuniao, em_reuniao: true, desta_sessao: true, ouvindo: true }
  mundo.hook = { sala: 'reuniao', publicado: true, motivo: '', pedida: 'amigo' }
  await $.tool.call({ tool: 'Write', file_path: '/x/deck.html', content: 'conteudo' })
  await relogio.settle()
  const ativ = mundo.chamadas.filter(c => c.includes('atividade'))
  expect(ativ.length).toBe(1)
  expect(ativ[0]!.slice(-5)).toEqual(['atividade', '--do-hook', '--json', '--sala', 'amigo'])
  expect(mundo.espiadas.at(-1)).toBe('reuniao')
  expect(mundo.toasts.some(t => /reuniao/.test(t))).toBe(true)
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text', text: /Sala reuniao/ })).toBeDefined()
  await ui.unmount()
})

test('HAR-005: o painel não rouba a sala de quem olha outra sala em reunião', async ($, on) => {
  const mundo = novoMundo()
  mundo.salas.amigo = { ...mundo.salas.amigo, em_reuniao: true }
  const relogio = motor(on, mundo)
  on('tool.call', () => ({ result: {} }))
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  expect(mundo.espiadas.at(-1)).toBe('amigo')
  mundo.hook = { sala: 'reuniao', publicado: true, motivo: '', pedida: 'amigo' }
  await $.tool.call({ tool: 'Edit', file_path: '/x/a.md' })
  await relogio.settle()
  expect(mundo.espiadas.at(-1)).toBe('amigo')
})

test('HAR-005: a cada minuto o painel confere a sala que a sessão ouve e segue sozinho', async ($, on) => {
  const mundo = novoMundo()
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  expect(mundo.espiadas.at(-1)).toBe('amigo')
  mundo.salas.reuniao = { ...mundo.salas.reuniao, em_reuniao: true, desta_sessao: true, ouvindo: true }
  await relogio.advance(61 * 1000)
  await relogio.settle()
  expect(mundo.espiadas.at(-1)).toBe('reuniao')
})

test('ao abrir a sessão, a sala em reunião desta sessão vem antes da guardada', async ($, on) => {
  const mundo = novoMundo()
  mundo.salas.reuniao = { ...mundo.salas.reuniao, em_reuniao: true, desta_sessao: true }
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  expect(mundo.espiadas.at(-1)).toBe('reuniao')
})

test('JP2: /sala nova devolve o link, /sala convidar copia e /sala entrar aceita o link JP2', async ($, on) => {
  const mundo = novoMundo()
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  mundo.salas.carlos = { nome: 'JARVIS da Ana', humano: 'Ana', servidor: 'https://ntfy.sh', usada_em: '2026-11-09T03:00:00' }
  const nova = await $.command.run({ command: 'sala', args: 'nova carlos-2' })
  expect(String(nova?.text)).toContain(`https://sala-jarvis.pages.dev/#${JP2}`)
  const conv = await $.command.run({ command: 'sala', args: 'convidar' })
  expect(String(conv?.text)).toContain(JP2)
  delete mundo.salas.carlos
  const entrou = await $.command.run({ command: 'sala', args: `entrar https://sala-jarvis.pages.dev/#${JP2} carlos` })
  expect(String(entrou?.text)).toContain("Entrei na sala 'carlos'")
  const e = mundo.chamadas.find(c => c.includes('entrar'))!
  expect(e[e.indexOf('entrar') + 1]).toBe(JP2)
})

test('a atividade vale pela dura e some quando o agente volta a ouvir', async ($, on) => {
  const mundo = novoMundo()
  mundo.salas.reuniao = { ...mundo.salas.reuniao, em_reuniao: true, desta_sessao: true }
  const agora = 1_800_000_000
  mundo.linhas.reuniao = [
    { tipo: 'vivo', sinal: 'atividade', id: 'v1', de: 'Lia', papel: 'agente', origem: 'agente-externo', acao: 'pensando', texto: 'lendo a mensagem nova', estado: 'aqui', validade: 660, dura: 600, time: agora - 400 },
  ]
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  let ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  // 400 s depois, ainda vale (dura 600; a 2.6 apagaria aos 90 s)
  expect(await ui.find({ type: 'Text', text: /lendo a mensagem nova/ })).toBeDefined()
  await ui.unmount()
  // a presença de quem voltou a ouvir encerra o rótulo
  mundo.linhas.reuniao = [
    ...mundo.linhas.reuniao,
    { tipo: 'vivo', sinal: 'presenca', id: 'v2', de: 'Lia', papel: 'agente', origem: 'agente-externo', acao: 'ouvindo', texto: '', estado: 'aqui', validade: 660, volta: true, time: agora - 10 },
  ]
  await $.command.run({ command: 'sala', args: 'trocar amigo' })
  await relogio.settle()
  await $.command.run({ command: 'sala', args: 'trocar reuniao' })
  await relogio.settle()
  ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text', text: /lendo a mensagem nova/ })).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: /ouvindo/ })).toBeDefined()
  await ui.unmount()
})

test('2.7: /sala encerrar pede confirmação e só encerra com "sim"; o painel mostra a sala encerrada', async ($, on) => {
  const mundo = novoMundo()
  mundo.salas.reuniao = { ...mundo.salas.reuniao, em_reuniao: true, desta_sessao: true }
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const pergunta = await $.command.run({ command: 'sala', args: 'encerrar' })
  expect(String(pergunta?.text)).toContain('/sala encerrar sim')
  expect(mundo.chamadas.some(c => c.includes('encerrar'))).toBe(false)
  const feito = await $.command.run({ command: 'sala', args: 'encerrar sim' })
  expect(String(feito?.text)).toContain('ENCERRADA')
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text', text: /encerrada/ })).toBeDefined()
  await ui.unmount()
})

test('2.7: /sala convidar jv1… manda o convite da sala ativa para a caixa do endereço', async ($, on) => {
  const mundo = novoMundo()
  mundo.salas.reuniao = { ...mundo.salas.reuniao, em_reuniao: true, desta_sessao: true }
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const end = 'jv1' + 'b'.repeat(58)
  const r = await $.command.run({ command: 'sala', args: `convidar ${end}` })
  expect(String(r?.text)).toContain('caixa')
  const m = mundo.chamadas.find(c => c.includes('mandar'))!
  expect(m.slice(m.indexOf('mandar'))).toEqual(['mandar', end, 'Convite para a sala reuniao', '--convite-da-sala', 'reuniao'])
  const e = await $.command.run({ command: 'sala', args: 'endereco' })
  expect(String(e?.text)).toContain('jv1')
})

test('2.7: a ponte diz que a sala acabou e o painel para de reabrir a escuta', async ($, on) => {
  const mundo = novoMundo()
  mundo.salas.reuniao = { ...mundo.salas.reuniao, em_reuniao: true, desta_sessao: true }
  mundo.linhas.reuniao = [{ tipo: 'encerrada', sala: 'reuniao', motivo: 'encerrada', por: 'JARVIS A', quando: '2026-11-09T03:00:00' }]
  const relogio = motor(on, mundo)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await relogio.settle()
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text', text: /A sala acabou/ })).toBeDefined()
  await ui.unmount()
})
