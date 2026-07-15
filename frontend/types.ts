import type { Coin } from '../types/coin'

export type NativeCoinRoute = `${string}-wallet` | 'quai-js' | 'qubic-js' | 'kaspa-wasm' | 'ckb-lumos'

type RuntimeCoinFields = 'balance' | 'fiatValue' | 'address' | 'status' | 'enabled' | 'favorite'
export type CoinDefinition = Omit<Coin, RuntimeCoinFields> & Partial<Pick<Coin, RuntimeCoinFields>>

export type CoinModule = {
  id: string
  nativeRoute: NativeCoinRoute
  coin: Coin
}

export const defineCoinModule = (
  definition: CoinDefinition,
  nativeRoute: NativeCoinRoute = `${definition.id}-wallet`,
): CoinModule => ({
  id: definition.id,
  nativeRoute,
  coin: {
    balance: '0',
    fiatValue: 0,
    address: '',
    status: 'syncing',
    enabled: true,
    favorite: false,
    ...definition,
  },
})
