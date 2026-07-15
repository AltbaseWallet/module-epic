import { defineCoinModule } from './types'

export default defineCoinModule({
  id: 'epic', name: 'Epic Cash', ticker: 'EPIC', networkId: 'epic-mainnet',
  supportsMemo: true, satsPerCoin: 100_000_000, walletEngine: 'epic-light',
}, 'epic-wallet')
