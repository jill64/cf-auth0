import { branchPreview, extendsConfig } from '@jill64/playwright-config'

export default extendsConfig({
  ...branchPreview(),
  workers: 1
})
