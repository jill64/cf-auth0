import { expect, test } from '@playwright/test'
import 'dotenv/config'
import { env } from 'node:process'

test('smoke', async ({ page }) => {
  await page.goto('/')

  await expect(page.getByText('Welcome')).toBeVisible()

  await page.getByText('Sign up').click()

  await page.getByLabel('Email address').fill(env.TEST_USER_EMAIL!)
  await page.getByLabel('Password').fill(env.TEST_USER_PASSWORD!)
  await page.click('button[type="submit"]')

  await page.getByText('Accept').click()

  await expect(page.getByText('Logged in !')).toBeVisible()

  await page.getByText('Logout').click()

  await expect(page.getByText('Welcome')).toBeVisible()

  await page.getByLabel('Email address').fill(env.TEST_USER_EMAIL!)
  await page.getByLabel('Password').fill(env.TEST_USER_PASSWORD!)
  await page.click('button[type="submit"]')

  await expect(page.getByText('Logged in !')).toBeVisible()

  await page.getByText('Delete Account').click()

  await expect(page.getByText('Welcome')).toBeVisible()

  await page.getByLabel('Email address').fill(env.TEST_USER_EMAIL!)
  await page.getByLabel('Password').fill(env.TEST_USER_PASSWORD!)
  await page.click('button[type="submit"]')

  await expect(page.getByText('Wrong email or password')).toBeVisible()
})
