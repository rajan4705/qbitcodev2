import { createContext, useContext, type ParentProps } from "solid-js"
import type { PromptRef } from "../component/prompt"

export type PromptContextType = {
  readonly current: PromptRef | undefined
  set(ref: PromptRef | undefined): void
}

let globalPromptRef: PromptRef | undefined

const fallbackContext: PromptContextType = {
  get current() {
    return globalPromptRef
  },
  set(ref: PromptRef | undefined) {
    globalPromptRef = ref
  },
}

const PromptContext = createContext<PromptContextType>(fallbackContext)

export function PromptRefProvider(props: ParentProps) {
  let current: PromptRef | undefined

  const value: PromptContextType = {
    get current() {
      return current ?? globalPromptRef
    },
    set(ref: PromptRef | undefined) {
      current = ref
      globalPromptRef = ref
    },
  }

  return <PromptContext.Provider value={value}>{props.children}</PromptContext.Provider>
}

export function usePromptRef(): PromptContextType {
  const value = useContext(PromptContext)
  return value ?? fallbackContext
}
