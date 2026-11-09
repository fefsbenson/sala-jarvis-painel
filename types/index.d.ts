// Contrato do estado da sala (validado por `claude plugin validate`).

export type SalaOrigem = 'eu' | 'meu-humano' | 'meu-humano-suspeito' | 'agente-externo' | 'humano-externo' | 'eu-suspeito' | 'assinatura-suspeita'

export type SalaAnexo = { nome: string; tam: number; sha256: string }

// uma mensagem da sala, como o `ponte.py espiar` entrega (texto já limpo de escape de terminal)
export type SalaMsg = {
  id: string
  de: string
  papel: 'agente' | 'humano'
  origem: SalaOrigem
  ts: string
  time: number
  texto: string
  anexos: SalaAnexo[]
  // ponte 2.5: 'sem' | 'sem-antes' | 'invalida' | 'minha' | 'nova' | 'conhecida' | 'trocada' | 'homonimo',
  // e o código de segurança
  assinatura?: string
  codigo?: string
}

// quem está na sala agora e o que está fazendo (canal vivo da ponte 2.3: efêmero, não fica guardado)
export type SalaVivo = {
  de: string
  papel: 'agente' | 'humano'
  origem: SalaOrigem
  acao: string
  texto: string
  estado: 'aqui' | 'saiu'
  time: number
  validade: number
  // ponte 2.7: quando a última atividade saiu e por quantos segundos ela vale (sem 'dura': 90 s, como a 2.6)
  ativEm?: number
  dura?: number
}

// a sala mostrada no painel
export type SalaInfo = {
  apelido: string
  eu: string
  humano: string
  ouvindo: boolean
  conexao: 'conectando' | 'ao-vivo' | 'caiu' | 'encerrada'
  desde: number
  // canal vivo (presença e atividade) desta sala: o `conectado` do espiar e o /sala vivo dizem; ausente = não se sabe
  vivo?: boolean
}

declare module 'claude-code' {
  interface PluginState {
    sala: {
      msgs: Shaped<SalaMsg[]>
      info: SalaInfo | null
      campo: number
      aviso: string
      naoLidas: number
      vivos: SalaVivo[]
    }
  }
}
